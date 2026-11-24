/**
 * Pure, side-effect-free Multi-Channel Fallback State Machine.
 * Zero I/O, deterministic transitions, explicit transition table,
 * and strict terminal-state rejection.
 */

export type DeliveryChannel = 'push' | 'sms' | 'email' | 'in_app' | 'none';

export type DeliveryStateName =
  | 'QUEUED'
  | 'ATTEMPTING'
  | 'AWAITING_ACK'
  | 'RETRY_WAIT'
  | 'FALLBACK'
  | 'DELIVERED_ACKED'
  | 'FAILED_ALL_CHANNELS'
  | 'CANCELLED'
  | 'EXPIRED';

export type DeliveryEventType =
  | 'START'
  | 'SEND_OK'
  | 'SEND_FAILED'
  | 'ACK_RECEIVED'
  | 'ACK_TIMEOUT'
  | 'RETRY_TIMER'
  | 'CANCEL'
  | 'EXPIRE';

export interface MachineState {
  state: DeliveryStateName;
  channel: DeliveryChannel;
}

export interface TransitionEvent {
  type: DeliveryEventType;
  /** Optional channel hint for QUEUED -> ATTEMPTING(channel) or FALLBACK */
  channel?: DeliveryChannel;
  /** Next fallback channel when retries are exhausted */
  nextChannel?: DeliveryChannel | null;
  /** Whether another retry is permitted on the current channel */
  canRetry?: boolean;
  /** Whether the policy requires explicit ACK (defaults to true) */
  requiresAck?: boolean;
}

export type TransitionAction =
  | 'BEGIN_CHANNEL_ATTEMPT'
  | 'BEGIN_FALLBACK_CHANNEL_ATTEMPT'
  | 'START_ACK_WAIT'
  | 'COMPLETE_NO_ACK_REQUIRED'
  | 'SCHEDULE_RETRY_BACKOFF'
  | 'SCHEDULE_RETRY_AFTER_ACK_TIMEOUT'
  | 'RETRY_CHANNEL_ATTEMPT'
  | 'FALLBACK_TO_NEXT_CHANNEL'
  | 'MARK_ALL_CHANNELS_FAILED'
  | 'RECORD_ACK_AND_STOP'
  | 'CANCEL_JOB'
  | 'EXPIRE_JOB';

export interface TransitionResult {
  from: MachineState;
  event: DeliveryEventType;
  to: MachineState;
  action: TransitionAction;
}

export interface TransitionTableEntry {
  id: string;
  from: DeliveryStateName;
  event: DeliveryEventType;
  condition: string;
  to: DeliveryStateName;
  channelBehavior: 'current' | 'target' | 'next' | 'none';
  action: TransitionAction;
  description: string;
}

export const ALL_STATES: readonly DeliveryStateName[] = [
  'QUEUED',
  'ATTEMPTING',
  'AWAITING_ACK',
  'RETRY_WAIT',
  'FALLBACK',
  'DELIVERED_ACKED',
  'FAILED_ALL_CHANNELS',
  'CANCELLED',
  'EXPIRED',
] as const;

export const ALL_EVENTS: readonly DeliveryEventType[] = [
  'START',
  'SEND_OK',
  'SEND_FAILED',
  'ACK_RECEIVED',
  'ACK_TIMEOUT',
  'RETRY_TIMER',
  'CANCEL',
  'EXPIRE',
] as const;

export const TERMINAL_STATES: readonly DeliveryStateName[] = [
  'DELIVERED_ACKED',
  'FAILED_ALL_CHANNELS',
  'CANCELLED',
  'EXPIRED',
] as const;

/**
 * Explicit, declarative transition table structured for both
 * verification tests and live state-machine diagram rendering.
 */
export const TRANSITION_TABLE: readonly TransitionTableEntry[] = [
  {
    id: 'queued-start',
    from: 'QUEUED',
    event: 'START',
    condition: 'hasTargetChannel',
    to: 'ATTEMPTING',
    channelBehavior: 'target',
    action: 'BEGIN_CHANNEL_ATTEMPT',
    description: 'Begin first channel attempt from queue.',
  },
  {
    id: 'attempting-send-ok-ack',
    from: 'ATTEMPTING',
    event: 'SEND_OK',
    condition: 'requiresAck == true',
    to: 'AWAITING_ACK',
    channelBehavior: 'current',
    action: 'START_ACK_WAIT',
    description: 'Dispatch succeeded; start acknowledgement timer.',
  },
  {
    id: 'attempting-send-ok-no-ack',
    from: 'ATTEMPTING',
    event: 'SEND_OK',
    condition: 'requiresAck == false',
    to: 'DELIVERED_ACKED',
    channelBehavior: 'current',
    action: 'COMPLETE_NO_ACK_REQUIRED',
    description: 'Dispatch succeeded for policy requiring no ACK.',
  },
  {
    id: 'attempting-send-failed-retry',
    from: 'ATTEMPTING',
    event: 'SEND_FAILED',
    condition: 'canRetry == true',
    to: 'RETRY_WAIT',
    channelBehavior: 'current',
    action: 'SCHEDULE_RETRY_BACKOFF',
    description: 'Send failed; wait exponential backoff before retry.',
  },
  {
    id: 'attempting-send-failed-fallback',
    from: 'ATTEMPTING',
    event: 'SEND_FAILED',
    condition: 'canRetry == false && hasNextChannel',
    to: 'FALLBACK',
    channelBehavior: 'next',
    action: 'FALLBACK_TO_NEXT_CHANNEL',
    description: 'Channel retries exhausted; advance to fallback channel.',
  },
  {
    id: 'attempting-send-failed-all',
    from: 'ATTEMPTING',
    event: 'SEND_FAILED',
    condition: 'canRetry == false && !hasNextChannel',
    to: 'FAILED_ALL_CHANNELS',
    channelBehavior: 'none',
    action: 'MARK_ALL_CHANNELS_FAILED',
    description: 'All configured channels failed; raise admin failure.',
  },
  {
    id: 'attempting-ack',
    from: 'ATTEMPTING',
    event: 'ACK_RECEIVED',
    condition: 'always',
    to: 'DELIVERED_ACKED',
    channelBehavior: 'current',
    action: 'RECORD_ACK_AND_STOP',
    description: 'User acknowledged during send; stop further escalation.',
  },
  {
    id: 'awaiting-ack-received',
    from: 'AWAITING_ACK',
    event: 'ACK_RECEIVED',
    condition: 'always',
    to: 'DELIVERED_ACKED',
    channelBehavior: 'current',
    action: 'RECORD_ACK_AND_STOP',
    description: 'User acknowledged within SLA window; delivery complete.',
  },
  {
    id: 'awaiting-ack-timeout-retry',
    from: 'AWAITING_ACK',
    event: 'ACK_TIMEOUT',
    condition: 'canRetry == true',
    to: 'RETRY_WAIT',
    channelBehavior: 'current',
    action: 'SCHEDULE_RETRY_AFTER_ACK_TIMEOUT',
    description: 'ACK timed out; schedule channel retry with backoff.',
  },
  {
    id: 'awaiting-ack-timeout-fallback',
    from: 'AWAITING_ACK',
    event: 'ACK_TIMEOUT',
    condition: 'canRetry == false && hasNextChannel',
    to: 'FALLBACK',
    channelBehavior: 'next',
    action: 'FALLBACK_TO_NEXT_CHANNEL',
    description: 'ACK timed out and retries exhausted; fall back to next channel.',
  },
  {
    id: 'awaiting-ack-timeout-failed',
    from: 'AWAITING_ACK',
    event: 'ACK_TIMEOUT',
    condition: 'canRetry == false && !hasNextChannel',
    to: 'FAILED_ALL_CHANNELS',
    channelBehavior: 'none',
    action: 'MARK_ALL_CHANNELS_FAILED',
    description: 'Final channel ACK timed out; mark all channels failed.',
  },
  {
    id: 'retry-wait-timer',
    from: 'RETRY_WAIT',
    event: 'RETRY_TIMER',
    condition: 'always',
    to: 'ATTEMPTING',
    channelBehavior: 'current',
    action: 'RETRY_CHANNEL_ATTEMPT',
    description: 'Backoff timer elapsed; re-attempt current channel.',
  },
  {
    id: 'retry-wait-ack',
    from: 'RETRY_WAIT',
    event: 'ACK_RECEIVED',
    condition: 'always',
    to: 'DELIVERED_ACKED',
    channelBehavior: 'current',
    action: 'RECORD_ACK_AND_STOP',
    description: 'User acknowledged while waiting for retry; complete job.',
  },
  {
    id: 'fallback-start',
    from: 'FALLBACK',
    event: 'START',
    condition: 'hasTargetChannel',
    to: 'ATTEMPTING',
    channelBehavior: 'current',
    action: 'BEGIN_FALLBACK_CHANNEL_ATTEMPT',
    description: 'Begin delivery attempt on fallback channel.',
  },
  {
    id: 'fallback-ack',
    from: 'FALLBACK',
    event: 'ACK_RECEIVED',
    condition: 'always',
    to: 'DELIVERED_ACKED',
    channelBehavior: 'current',
    action: 'RECORD_ACK_AND_STOP',
    description: 'User acknowledged prior to fallback dispatch; complete job.',
  },
  // Universal non-terminal lifecycle exits
  {
    id: 'queued-cancel',
    from: 'QUEUED',
    event: 'CANCEL',
    condition: 'nonTerminal',
    to: 'CANCELLED',
    channelBehavior: 'none',
    action: 'CANCEL_JOB',
    description: 'Cancel queued job before dispatch.',
  },
  {
    id: 'attempting-cancel',
    from: 'ATTEMPTING',
    event: 'CANCEL',
    condition: 'nonTerminal',
    to: 'CANCELLED',
    channelBehavior: 'none',
    action: 'CANCEL_JOB',
    description: 'Cancel job during channel attempt.',
  },
  {
    id: 'awaiting-ack-cancel',
    from: 'AWAITING_ACK',
    event: 'CANCEL',
    condition: 'nonTerminal',
    to: 'CANCELLED',
    channelBehavior: 'none',
    action: 'CANCEL_JOB',
    description: 'Cancel job while awaiting user acknowledgement.',
  },
  {
    id: 'retry-wait-cancel',
    from: 'RETRY_WAIT',
    event: 'CANCEL',
    condition: 'nonTerminal',
    to: 'CANCELLED',
    channelBehavior: 'none',
    action: 'CANCEL_JOB',
    description: 'Cancel job during retry backoff wait.',
  },
  {
    id: 'fallback-cancel',
    from: 'FALLBACK',
    event: 'CANCEL',
    condition: 'nonTerminal',
    to: 'CANCELLED',
    channelBehavior: 'none',
    action: 'CANCEL_JOB',
    description: 'Cancel job during fallback transition.',
  },
  {
    id: 'queued-expire',
    from: 'QUEUED',
    event: 'EXPIRE',
    condition: 'nonTerminal',
    to: 'EXPIRED',
    channelBehavior: 'none',
    action: 'EXPIRE_JOB',
    description: 'Expire queued job past TTL.',
  },
  {
    id: 'attempting-expire',
    from: 'ATTEMPTING',
    event: 'EXPIRE',
    condition: 'nonTerminal',
    to: 'EXPIRED',
    channelBehavior: 'none',
    action: 'EXPIRE_JOB',
    description: 'Expire attempting job past TTL.',
  },
  {
    id: 'awaiting-ack-expire',
    from: 'AWAITING_ACK',
    event: 'EXPIRE',
    condition: 'nonTerminal',
    to: 'EXPIRED',
    channelBehavior: 'none',
    action: 'EXPIRE_JOB',
    description: 'Expire awaiting-ack job past TTL.',
  },
  {
    id: 'retry-wait-expire',
    from: 'RETRY_WAIT',
    event: 'EXPIRE',
    condition: 'nonTerminal',
    to: 'EXPIRED',
    channelBehavior: 'none',
    action: 'EXPIRE_JOB',
    description: 'Expire retry-waiting job past TTL.',
  },
  {
    id: 'fallback-expire',
    from: 'FALLBACK',
    event: 'EXPIRE',
    condition: 'nonTerminal',
    to: 'EXPIRED',
    channelBehavior: 'none',
    action: 'EXPIRE_JOB',
    description: 'Expire fallback job past TTL.',
  },
] as const;

export class IllegalTransitionError extends Error {
  readonly fromState: DeliveryStateName;
  readonly eventType: DeliveryEventType;

  constructor(fromState: DeliveryStateName, eventType: DeliveryEventType, reason: string) {
    super(`Illegal delivery state transition: (${fromState}) + [${eventType}] -> ${reason}`);
    this.name = 'IllegalTransitionError';
    this.fromState = fromState;
    this.eventType = eventType;
  }
}

export function isTerminalState(state: DeliveryStateName): boolean {
  return TERMINAL_STATES.includes(state);
}

export function formatMachineState(ms: MachineState): string {
  if (
    ms.state === 'ATTEMPTING' ||
    ms.state === 'AWAITING_ACK' ||
    ms.state === 'RETRY_WAIT' ||
    ms.state === 'FALLBACK'
  ) {
    return `${ms.state}(${ms.channel})`;
  }
  return ms.state;
}

/**
 * Pure deterministic transition function.
 * Throws IllegalTransitionError on any illegal transition or event applied to a terminal state.
 */
export function transition(current: MachineState, event: TransitionEvent): TransitionResult {
  if (isTerminalState(current.state)) {
    throw new IllegalTransitionError(
      current.state,
      event.type,
      'terminal state accepts no further events'
    );
  }

  // Handle universal CANCEL / EXPIRE for all non-terminal states
  if (event.type === 'CANCEL') {
    return {
      from: current,
      event: event.type,
      to: { state: 'CANCELLED', channel: 'none' },
      action: 'CANCEL_JOB',
    };
  }

  if (event.type === 'EXPIRE') {
    return {
      from: current,
      event: event.type,
      to: { state: 'EXPIRED', channel: 'none' },
      action: 'EXPIRE_JOB',
    };
  }

  switch (current.state) {
    case 'QUEUED': {
      if (event.type === 'START') {
        const targetChannel = event.channel && event.channel !== 'none' ? event.channel : current.channel;
        if (!targetChannel || targetChannel === 'none') {
          throw new IllegalTransitionError(
            current.state,
            event.type,
            'target channel is required when starting a queued job'
          );
        }
        return {
          from: current,
          event: event.type,
          to: { state: 'ATTEMPTING', channel: targetChannel },
          action: 'BEGIN_CHANNEL_ATTEMPT',
        };
      }
      throw new IllegalTransitionError(current.state, event.type, 'QUEUED only accepts START, CANCEL, or EXPIRE');
    }

    case 'ATTEMPTING': {
      if (event.type === 'SEND_OK') {
        const requiresAck = event.requiresAck !== false;
        if (!requiresAck) {
          return {
            from: current,
            event: event.type,
            to: { state: 'DELIVERED_ACKED', channel: current.channel },
            action: 'COMPLETE_NO_ACK_REQUIRED',
          };
        }
        return {
          from: current,
          event: event.type,
          to: { state: 'AWAITING_ACK', channel: current.channel },
          action: 'START_ACK_WAIT',
        };
      }

      if (event.type === 'SEND_FAILED') {
        if (event.canRetry) {
          return {
            from: current,
            event: event.type,
            to: { state: 'RETRY_WAIT', channel: current.channel },
            action: 'SCHEDULE_RETRY_BACKOFF',
          };
        }
        if (event.nextChannel && event.nextChannel !== 'none') {
          return {
            from: current,
            event: event.type,
            to: { state: 'FALLBACK', channel: event.nextChannel },
            action: 'FALLBACK_TO_NEXT_CHANNEL',
          };
        }
        return {
          from: current,
          event: event.type,
          to: { state: 'FAILED_ALL_CHANNELS', channel: 'none' },
          action: 'MARK_ALL_CHANNELS_FAILED',
        };
      }

      if (event.type === 'ACK_RECEIVED') {
        return {
          from: current,
          event: event.type,
          to: { state: 'DELIVERED_ACKED', channel: current.channel },
          action: 'RECORD_ACK_AND_STOP',
        };
      }

      throw new IllegalTransitionError(
        current.state,
        event.type,
        'ATTEMPTING only accepts SEND_OK, SEND_FAILED, ACK_RECEIVED, CANCEL, or EXPIRE'
      );
    }

    case 'AWAITING_ACK': {
      if (event.type === 'ACK_RECEIVED') {
        return {
          from: current,
          event: event.type,
          to: { state: 'DELIVERED_ACKED', channel: current.channel },
          action: 'RECORD_ACK_AND_STOP',
        };
      }

      if (event.type === 'ACK_TIMEOUT') {
        if (event.canRetry) {
          return {
            from: current,
            event: event.type,
            to: { state: 'RETRY_WAIT', channel: current.channel },
            action: 'SCHEDULE_RETRY_AFTER_ACK_TIMEOUT',
          };
        }
        if (event.nextChannel && event.nextChannel !== 'none') {
          return {
            from: current,
            event: event.type,
            to: { state: 'FALLBACK', channel: event.nextChannel },
            action: 'FALLBACK_TO_NEXT_CHANNEL',
          };
        }
        return {
          from: current,
          event: event.type,
          to: { state: 'FAILED_ALL_CHANNELS', channel: 'none' },
          action: 'MARK_ALL_CHANNELS_FAILED',
        };
      }

      throw new IllegalTransitionError(
        current.state,
        event.type,
        'AWAITING_ACK only accepts ACK_RECEIVED, ACK_TIMEOUT, CANCEL, or EXPIRE'
      );
    }

    case 'RETRY_WAIT': {
      if (event.type === 'RETRY_TIMER') {
        return {
          from: current,
          event: event.type,
          to: { state: 'ATTEMPTING', channel: current.channel },
          action: 'RETRY_CHANNEL_ATTEMPT',
        };
      }

      if (event.type === 'ACK_RECEIVED') {
        return {
          from: current,
          event: event.type,
          to: { state: 'DELIVERED_ACKED', channel: current.channel },
          action: 'RECORD_ACK_AND_STOP',
        };
      }

      throw new IllegalTransitionError(
        current.state,
        event.type,
        'RETRY_WAIT only accepts RETRY_TIMER, ACK_RECEIVED, CANCEL, or EXPIRE'
      );
    }

    case 'FALLBACK': {
      if (event.type === 'START') {
        const nextChannel =
          event.channel && event.channel !== 'none' ? event.channel : current.channel;
        if (!nextChannel || nextChannel === 'none') {
          throw new IllegalTransitionError(
            current.state,
            event.type,
            'FALLBACK START requires a valid fallback channel'
          );
        }
        return {
          from: current,
          event: event.type,
          to: { state: 'ATTEMPTING', channel: nextChannel },
          action: 'BEGIN_FALLBACK_CHANNEL_ATTEMPT',
        };
      }

      if (event.type === 'ACK_RECEIVED') {
        return {
          from: current,
          event: event.type,
          to: { state: 'DELIVERED_ACKED', channel: current.channel },
          action: 'RECORD_ACK_AND_STOP',
        };
      }

      throw new IllegalTransitionError(
        current.state,
        event.type,
        'FALLBACK only accepts START, ACK_RECEIVED, CANCEL, or EXPIRE'
      );
    }

    default:
      throw new IllegalTransitionError(current.state, event.type, 'unrecognized state');
  }
}
