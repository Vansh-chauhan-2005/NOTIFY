import { describe, expect, it } from 'vitest';
import {
  ALL_EVENTS,
  TERMINAL_STATES,
  TRANSITION_TABLE,
  IllegalTransitionError,
  formatMachineState,
  isTerminalState,
  transition,
  type DeliveryEventType,
} from '../stateMachine.js';
import {
  DELIVERY_POLICIES,
  calculateBackoffMs,
  getPolicyForPriority,
  isWithinQuietHours,
  normalizePriority,
  resolveEffectiveDeliveryPlan,
} from '../policies.js';
import { createSignedAckToken, verifyAndConsumeAckToken } from '../ackTokens.js';

describe('Multi-Channel Fallback Pure State Machine', () => {
  it('exposes explicit transition table and terminal states', () => {
    expect(TRANSITION_TABLE.length).toBeGreaterThanOrEqual(20);
    expect(TERMINAL_STATES).toEqual([
      'DELIVERED_ACKED',
      'FAILED_ALL_CHANNELS',
      'CANCELLED',
      'EXPIRED',
    ]);
    for (const s of TERMINAL_STATES) {
      expect(isTerminalState(s)).toBe(true);
    }
    expect(isTerminalState('QUEUED')).toBe(false);
    expect(formatMachineState({ state: 'AWAITING_ACK', channel: 'sms' })).toBe('AWAITING_ACK(sms)');
    expect(formatMachineState({ state: 'DELIVERED_ACKED', channel: 'push' })).toBe('DELIVERED_ACKED');
  });

  it('handles every legal transition from QUEUED', () => {
    const startRes = transition({ state: 'QUEUED', channel: 'push' }, { type: 'START', channel: 'push' });
    expect(startRes.to).toEqual({ state: 'ATTEMPTING', channel: 'push' });
    expect(startRes.action).toBe('BEGIN_CHANNEL_ATTEMPT');

    expect(transition({ state: 'QUEUED', channel: 'push' }, { type: 'CANCEL' }).to.state).toBe('CANCELLED');
    expect(transition({ state: 'QUEUED', channel: 'push' }, { type: 'EXPIRE' }).to.state).toBe('EXPIRED');
  });

  it('rejects illegal transitions from QUEUED', () => {
    const illegal: DeliveryEventType[] = [
      'SEND_OK',
      'SEND_FAILED',
      'ACK_RECEIVED',
      'ACK_TIMEOUT',
      'RETRY_TIMER',
    ];
    for (const evt of illegal) {
      expect(() => transition({ state: 'QUEUED', channel: 'push' }, { type: evt })).toThrowError(
        IllegalTransitionError
      );
    }
  });

  it('handles every legal transition from ATTEMPTING', () => {
    const okAck = transition(
      { state: 'ATTEMPTING', channel: 'push' },
      { type: 'SEND_OK', requiresAck: true }
    );
    expect(okAck.to).toEqual({ state: 'AWAITING_ACK', channel: 'push' });

    const okNoAck = transition(
      { state: 'ATTEMPTING', channel: 'in_app' },
      { type: 'SEND_OK', requiresAck: false }
    );
    expect(okNoAck.to).toEqual({ state: 'DELIVERED_ACKED', channel: 'in_app' });

    const failRetry = transition(
      { state: 'ATTEMPTING', channel: 'push' },
      { type: 'SEND_FAILED', canRetry: true }
    );
    expect(failRetry.to).toEqual({ state: 'RETRY_WAIT', channel: 'push' });

    const failFallback = transition(
      { state: 'ATTEMPTING', channel: 'push' },
      { type: 'SEND_FAILED', canRetry: false, nextChannel: 'sms' }
    );
    expect(failFallback.to).toEqual({ state: 'FALLBACK', channel: 'sms' });

    const failAll = transition(
      { state: 'ATTEMPTING', channel: 'email' },
      { type: 'SEND_FAILED', canRetry: false, nextChannel: null }
    );
    expect(failAll.to).toEqual({ state: 'FAILED_ALL_CHANNELS', channel: 'none' });

    expect(
      transition({ state: 'ATTEMPTING', channel: 'push' }, { type: 'ACK_RECEIVED' }).to.state
    ).toBe('DELIVERED_ACKED');
    expect(transition({ state: 'ATTEMPTING', channel: 'push' }, { type: 'CANCEL' }).to.state).toBe(
      'CANCELLED'
    );
    expect(transition({ state: 'ATTEMPTING', channel: 'push' }, { type: 'EXPIRE' }).to.state).toBe(
      'EXPIRED'
    );
  });

  it('rejects illegal transitions from ATTEMPTING', () => {
    const illegal: DeliveryEventType[] = ['START', 'ACK_TIMEOUT', 'RETRY_TIMER'];
    for (const evt of illegal) {
      expect(() =>
        transition({ state: 'ATTEMPTING', channel: 'push' }, { type: evt })
      ).toThrowError(IllegalTransitionError);
    }
  });

  it('handles every legal transition from AWAITING_ACK and rejects illegal ones', () => {
    const acked = transition({ state: 'AWAITING_ACK', channel: 'sms' }, { type: 'ACK_RECEIVED' });
    expect(acked.to).toEqual({ state: 'DELIVERED_ACKED', channel: 'sms' });

    const timeoutRetry = transition(
      { state: 'AWAITING_ACK', channel: 'push' },
      { type: 'ACK_TIMEOUT', canRetry: true }
    );
    expect(timeoutRetry.to).toEqual({ state: 'RETRY_WAIT', channel: 'push' });

    const timeoutFallback = transition(
      { state: 'AWAITING_ACK', channel: 'push' },
      { type: 'ACK_TIMEOUT', canRetry: false, nextChannel: 'sms' }
    );
    expect(timeoutFallback.to).toEqual({ state: 'FALLBACK', channel: 'sms' });

    const timeoutExhausted = transition(
      { state: 'AWAITING_ACK', channel: 'email' },
      { type: 'ACK_TIMEOUT', canRetry: false, nextChannel: null }
    );
    expect(timeoutExhausted.to).toEqual({ state: 'FAILED_ALL_CHANNELS', channel: 'none' });

    expect(transition({ state: 'AWAITING_ACK', channel: 'sms' }, { type: 'CANCEL' }).to.state).toBe(
      'CANCELLED'
    );
    expect(transition({ state: 'AWAITING_ACK', channel: 'sms' }, { type: 'EXPIRE' }).to.state).toBe(
      'EXPIRED'
    );

    const illegal: DeliveryEventType[] = ['START', 'SEND_OK', 'SEND_FAILED', 'RETRY_TIMER'];
    for (const evt of illegal) {
      expect(() =>
        transition({ state: 'AWAITING_ACK', channel: 'sms' }, { type: evt })
      ).toThrowError(IllegalTransitionError);
    }
  });

  it('handles every legal transition from RETRY_WAIT and FALLBACK and rejects illegal ones', () => {
    expect(
      transition({ state: 'RETRY_WAIT', channel: 'push' }, { type: 'RETRY_TIMER' }).to
    ).toEqual({ state: 'ATTEMPTING', channel: 'push' });
    expect(
      transition({ state: 'RETRY_WAIT', channel: 'push' }, { type: 'ACK_RECEIVED' }).to.state
    ).toBe('DELIVERED_ACKED');
    expect(transition({ state: 'RETRY_WAIT', channel: 'push' }, { type: 'CANCEL' }).to.state).toBe(
      'CANCELLED'
    );
    expect(transition({ state: 'RETRY_WAIT', channel: 'push' }, { type: 'EXPIRE' }).to.state).toBe(
      'EXPIRED'
    );

    for (const evt of ['START', 'SEND_OK', 'SEND_FAILED', 'ACK_TIMEOUT'] as DeliveryEventType[]) {
      expect(() =>
        transition({ state: 'RETRY_WAIT', channel: 'push' }, { type: evt })
      ).toThrowError(IllegalTransitionError);
    }

    expect(transition({ state: 'FALLBACK', channel: 'sms' }, { type: 'START' }).to).toEqual({
      state: 'ATTEMPTING',
      channel: 'sms',
    });
    expect(
      transition({ state: 'FALLBACK', channel: 'sms' }, { type: 'ACK_RECEIVED' }).to.state
    ).toBe('DELIVERED_ACKED');
    expect(transition({ state: 'FALLBACK', channel: 'sms' }, { type: 'CANCEL' }).to.state).toBe(
      'CANCELLED'
    );
    expect(transition({ state: 'FALLBACK', channel: 'sms' }, { type: 'EXPIRE' }).to.state).toBe(
      'EXPIRED'
    );

    for (const evt of [
      'SEND_OK',
      'SEND_FAILED',
      'ACK_TIMEOUT',
      'RETRY_TIMER',
    ] as DeliveryEventType[]) {
      expect(() =>
        transition({ state: 'FALLBACK', channel: 'sms' }, { type: evt })
      ).toThrowError(IllegalTransitionError);
    }
  });

  it('rejects ALL events once a job reaches ANY terminal state', () => {
    for (const terminal of TERMINAL_STATES) {
      for (const evt of ALL_EVENTS) {
        expect(() =>
          transition({ state: terminal, channel: 'push' }, { type: evt, channel: 'sms' })
        ).toThrowError(IllegalTransitionError);
      }
    }
  });
});

describe('Delivery Policies, Backoff Jitter & Quiet Hours', () => {
  it('computes exponential backoff (2s, 4s) within bounded jitter range', () => {
    expect(calculateBackoffMs(0, 2000, 0.25, () => 0)).toBe(2000);
    expect(calculateBackoffMs(0, 2000, 0.25, () => 1)).toBe(2500);
    expect(calculateBackoffMs(1, 2000, 0.25, () => 0)).toBe(4000);
    expect(calculateBackoffMs(1, 2000, 0.25, () => 1)).toBe(5000);
  });

  it('selects exact delivery policies per priority level', () => {
    expect(DELIVERY_POLICIES.CRITICAL.channels).toEqual(['push', 'whatsapp', 'sms', 'email']);
    expect(DELIVERY_POLICIES.CRITICAL.ackTimeoutMs).toBe(30_000);
    expect(DELIVERY_POLICIES.CRITICAL.maxRetriesPerChannel).toBe(2);

    expect(DELIVERY_POLICIES.HIGH.channels).toEqual(['push', 'whatsapp', 'email']);
    expect(DELIVERY_POLICIES.HIGH.ackTimeoutMs).toBe(120_000);
    expect(DELIVERY_POLICIES.HIGH.maxRetriesPerChannel).toBe(1);

    expect(getPolicyForPriority('MEDIUM').priority).toBe('NORMAL');
    expect(normalizePriority('NORMAL')).toBe('NORMAL');
    expect(DELIVERY_POLICIES.NORMAL.channels).toEqual(['push', 'in_app']);
    expect(DELIVERY_POLICIES.NORMAL.requiresAck).toBe(false);

    expect(DELIVERY_POLICIES.LOW.channels).toEqual(['in_app']);
    expect(DELIVERY_POLICIES.LOW.digestOnly).toBe(true);
  });

  it('enforces quiet hours unless CRITICAL bypass is permitted by user, and honors opt-outs', () => {
    const nightTime = new Date('2026-11-21T23:30:00');
    const prefs = {
      dndEnabled: true,
      quietHoursStart: '22:00',
      quietHoursEnd: '07:00',
      allowCriticalBypassQuietHours: true,
      optOutSms: true,
    };

    expect(isWithinQuietHours(prefs, nightTime)).toBe(true);

    const highPlan = resolveEffectiveDeliveryPlan('HIGH', prefs, { now: nightTime });
    expect(highPlan.channels).toEqual(['in_app']);
    expect(highPlan.quietHoursBypassed).toBe(false);

    const criticalBypassPlan = resolveEffectiveDeliveryPlan('CRITICAL', prefs, { now: nightTime });
    expect(criticalBypassPlan.quietHoursBypassed).toBe(true);
    expect(criticalBypassPlan.channels).toEqual(['push', 'whatsapp', 'email']);

    const criticalWithWhatsappOptOut = resolveEffectiveDeliveryPlan(
      'CRITICAL',
      { ...prefs, optOutWhatsapp: true },
      { now: nightTime }
    );
    expect(criticalWithWhatsappOptOut.channels).toEqual(['push', 'email']);

    const whatsappPreferred = resolveEffectiveDeliveryPlan('HIGH', {
      preferredChannel: 'WHATSAPP',
    });
    expect(whatsappPreferred.channels).toEqual(['whatsapp', 'push', 'email']);

    const criticalNoBypass = resolveEffectiveDeliveryPlan(
      'CRITICAL',
      { ...prefs, allowCriticalBypassQuietHours: false },
      { now: nightTime }
    );
    expect(criticalNoBypass.quietHoursBypassed).toBe(false);
    expect(criticalNoBypass.channels).toEqual(['in_app']);
  });
});

describe('Signed Single-Use ACK Links', () => {
  it('verifies a valid token once and rejects replay or tampering', () => {
    const { token } = createSignedAckToken('dlv_test_job_1', 'usr_demo_1');
    const first = verifyAndConsumeAckToken(token, 'dlv_test_job_1');
    expect(first.valid).toBe(true);
    expect(first.payload?.j).toBe('dlv_test_job_1');

    const replay = verifyAndConsumeAckToken(token, 'dlv_test_job_1');
    expect(replay.valid).toBe(false);

    const tampered = verifyAndConsumeAckToken(`${token}tampered`, 'dlv_test_job_1');
    expect(tampered.valid).toBe(false);
  });
});
