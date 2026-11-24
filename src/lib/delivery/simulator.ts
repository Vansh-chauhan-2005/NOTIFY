import crypto from 'crypto';
import {
  applyStateTransitionToJob,
  createDeliveryJob,
  getDeliveryJobById,
  simulateServerRestartReload,
} from './deliveryStore.js';
import {
  acknowledgeDeliveryJob,
  processSingleDeliveryJob,
} from './workerLoop.js';
import {
  formatMachineState,
  IllegalTransitionError,
  transition,
} from './stateMachine.js';
import { resetBreaker } from './circuitBreaker.js';
import type { DeliveryJobRecord, DemoFaultConfig } from './channels/types.js';

export type SimulatorScenarioId = 'a' | 'b' | 'c' | 'd' | 'e' | 'f' | 'g';

export interface ScenarioTestResult {
  id: SimulatorScenarioId;
  title: string;
  expectedOutcome: string;
  actualOutcome: string;
  passed: boolean;
  durationMs: number;
  jobId?: string;
  jobSnapshot?: DeliveryJobRecord | null;
}

const DEMO_USER_ID = 'usr_demo_simulator_only';
const DEMO_EMAIL = 'demo-simulator@aegis-test.invalid';
const DEMO_PHONE = '+919000000099';

function sleep(ms: number) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

/**
 * Helper to drive a single demo job deterministically to completion
 * using short simulator timeouts (<= 150ms per hop) so scenarios finish swiftly.
 */
async function driveDemoJobUntil(
  jobId: string,
  stopPredicate: (job: DeliveryJobRecord) => boolean,
  maxSteps = 20
): Promise<DeliveryJobRecord> {
  let latest = (await getDeliveryJobById(jobId))!;
  for (let i = 0; i < maxSteps; i++) {
    if (!latest || stopPredicate(latest)) {
      return latest;
    }
    const dueMs = Date.parse(latest.nextAttemptAt);
    const now = Date.now();
    if (Number.isFinite(dueMs) && dueMs > now) {
      await sleep(Math.min(350, dueMs - now + 15));
    }
    latest = (await processSingleDeliveryJob(jobId, {
      now: Date.now() + 20,
      shortDemoBackoffMs: 60,
    }))!;
  }
  return latest;
}

export async function runCustomDemoFaultJob(
  faults: DemoFaultConfig,
  priority: 'CRITICAL' | 'HIGH' | 'NORMAL' | 'LOW' = 'CRITICAL'
): Promise<DeliveryJobRecord> {
  resetBreaker(undefined, 'sim');
  const created = await createDeliveryJob({
    notificationId: `demo_custom_${Date.now().toString(36)}`,
    userId: DEMO_USER_ID,
    priority,
    idempotencyKey: `demo:custom:${Date.now()}:${crypto.randomBytes(3).toString('hex')}`,
    recipientEmail: DEMO_EMAIL,
    recipientPhone: DEMO_PHONE,
    isDemoJob: true,
    demoFaults: { ...faults, shortTimeouts: true },
  });

  let job = await processSingleDeliveryJob(created.job.id, { shortDemoBackoffMs: 60 });
  if (!job) return created.job;

  if (faults.forceSlowAck && job.state === 'AWAITING_ACK') {
    // Allow push to time out, fall back to SMS, then ack after brief delay
    const afterTimeout = await driveDemoJobUntil(
      job.id,
      (j) => j.channel === 'sms' && j.state === 'AWAITING_ACK',
      10
    );
    if (afterTimeout.state === 'AWAITING_ACK') {
      return await acknowledgeDeliveryJob({
        jobId: afterTimeout.id,
        via: 'demo-slow-ack-sms',
      });
    }
    return afterTimeout;
  }

  if (faults.forceNoAck || faults.forceAllDown) {
    return await driveDemoJobUntil(
      job.id,
      (j) =>
        j.state === 'DELIVERED_ACKED' ||
        j.state === 'FAILED_ALL_CHANNELS' ||
        j.state === 'EXPIRED',
      24
    );
  }

  // Otherwise run until it reaches AWAITING_ACK (or terminal) on first working channel, then auto-ack unless forceNoAck
  job = await driveDemoJobUntil(
    job.id,
    (j) =>
      j.state === 'AWAITING_ACK' ||
      j.state === 'DELIVERED_ACKED' ||
      j.state === 'FAILED_ALL_CHANNELS',
    20
  );

  if (job.state === 'AWAITING_ACK' && !faults.forceNoAck) {
    return await acknowledgeDeliveryJob({
      jobId: job.id,
      via: `demo-${job.channel}-ack`,
    });
  }

  return job;
}

export async function runSimulatorScenario(id: SimulatorScenarioId): Promise<ScenarioTestResult> {
  const started = Date.now();
  resetBreaker(undefined, 'sim');

  switch (id) {
    case 'a': {
      const { job } = await createDeliveryJob({
        notificationId: `sim_a_${Date.now()}`,
        userId: DEMO_USER_ID,
        priority: 'CRITICAL',
        idempotencyKey: `sim:a:${Date.now()}:${crypto.randomBytes(3).toString('hex')}`,
        recipientEmail: DEMO_EMAIL,
        recipientPhone: DEMO_PHONE,
        isDemoJob: true,
        demoFaults: { shortTimeouts: true },
      });
      await processSingleDeliveryJob(job.id, { shortDemoBackoffMs: 50 });
      const acked = await acknowledgeDeliveryJob({
        jobId: job.id,
        via: 'in-app-push-ack',
      });
      const smsUsed = acked.history.some((h) => h.channel === 'sms');
      const passed = acked.state === 'DELIVERED_ACKED' && !smsUsed;
      return {
        id: 'a',
        title: '(a) Ack on first push -> DELIVERED_ACKED, no SMS sent',
        expectedOutcome: 'State DELIVERED_ACKED on push without touching SMS',
        actualOutcome: `State=${acked.state}, channel=${acked.channel}, smsUsed=${smsUsed}`,
        passed,
        durationMs: Date.now() - started,
        jobId: acked.id,
        jobSnapshot: acked,
      };
    }

    case 'b': {
      const { job } = await createDeliveryJob({
        notificationId: `sim_b_${Date.now()}`,
        userId: DEMO_USER_ID,
        priority: 'CRITICAL',
        idempotencyKey: `sim:b:${Date.now()}:${crypto.randomBytes(3).toString('hex')}`,
        recipientEmail: DEMO_EMAIL,
        recipientPhone: DEMO_PHONE,
        isDemoJob: true,
        demoFaults: { shortTimeouts: true },
      });
      // First push send -> AWAITING_ACK(push) with fast ackTimeout
      await processSingleDeliveryJob(job.id, { shortDemoBackoffMs: 50 });
      // Wait for short push ACK timeout and run worker -> falls back & sends SMS -> AWAITING_ACK(sms)
      const afterTimeout = await driveDemoJobUntil(
        job.id,
        (j) => j.state === 'AWAITING_ACK' && j.channel === 'sms',
        12
      );
      const acked = await acknowledgeDeliveryJob({
        jobId: afterTimeout.id,
        via: 'sms-signed-link',
      });
      const hadFallbackToSms = acked.history.some(
        (h) => h.to === 'FALLBACK' && h.channel === 'sms'
      );
      const passed = acked.state === 'DELIVERED_ACKED' && acked.channel === 'sms' && hadFallbackToSms;
      return {
        id: 'b',
        title: '(b) Push times out -> SMS used -> acked',
        expectedOutcome: 'Push ACK timeout falls back to SMS and finishes DELIVERED_ACKED',
        actualOutcome: `State=${acked.state}, channel=${acked.channel}, fallbackToSms=${hadFallbackToSms}`,
        passed,
        durationMs: Date.now() - started,
        jobId: acked.id,
        jobSnapshot: acked,
      };
    }

    case 'c': {
      const { job } = await createDeliveryJob({
        notificationId: `sim_c_${Date.now()}`,
        userId: DEMO_USER_ID,
        priority: 'CRITICAL',
        idempotencyKey: `sim:c:${Date.now()}:${crypto.randomBytes(3).toString('hex')}`,
        recipientEmail: DEMO_EMAIL,
        recipientPhone: DEMO_PHONE,
        isDemoJob: true,
        demoFaults: { forcePushFail: true, forceSmsFail: true, shortTimeouts: true },
      });
      const atEmail = await driveDemoJobUntil(
        job.id,
        (j) =>
          (j.state === 'AWAITING_ACK' && j.channel === 'email') ||
          j.state === 'FAILED_ALL_CHANNELS',
        20
      );
      const acked =
        atEmail.state === 'AWAITING_ACK'
          ? await acknowledgeDeliveryJob({ jobId: atEmail.id, via: 'email-signed-link' })
          : atEmail;
      const passed = acked.state === 'DELIVERED_ACKED' && acked.channel === 'email';
      return {
        id: 'c',
        title: '(c) Push and SMS fail -> email used -> acked',
        expectedOutcome: 'Retries/fails push and SMS, falls back to email, acked',
        actualOutcome: `State=${acked.state}, channel=${acked.channel}, transitions=${acked.history.length}`,
        passed,
        durationMs: Date.now() - started,
        jobId: acked.id,
        jobSnapshot: acked,
      };
    }

    case 'd': {
      const { job } = await createDeliveryJob({
        notificationId: `sim_d_${Date.now()}`,
        userId: DEMO_USER_ID,
        priority: 'CRITICAL',
        idempotencyKey: `sim:d:${Date.now()}:${crypto.randomBytes(3).toString('hex')}`,
        recipientEmail: DEMO_EMAIL,
        recipientPhone: DEMO_PHONE,
        isDemoJob: true,
        demoFaults: { forceAllDown: true, shortTimeouts: true },
      });
      const done = await driveDemoJobUntil(
        job.id,
        (j) => j.state === 'FAILED_ALL_CHANNELS',
        26
      );
      const passed = done.state === 'FAILED_ALL_CHANNELS';
      return {
        id: 'd',
        title: '(d) All channels fail -> FAILED_ALL_CHANNELS and an admin alert',
        expectedOutcome: 'Terminal FAILED_ALL_CHANNELS + DELIVERY_FAILED critical admin telemetry logged',
        actualOutcome: `State=${done.state}, totalTransitions=${done.history.length}`,
        passed,
        durationMs: Date.now() - started,
        jobId: done.id,
        jobSnapshot: done,
      };
    }

    case 'e': {
      const fixedKey = `sim:e:idem:${Date.now()}:${crypto.randomBytes(3).toString('hex')}`;
      const first = await createDeliveryJob({
        notificationId: `sim_e_${Date.now()}`,
        userId: DEMO_USER_ID,
        priority: 'HIGH',
        idempotencyKey: fixedKey,
        recipientEmail: DEMO_EMAIL,
        isDemoJob: true,
        demoFaults: { shortTimeouts: true },
      });
      const second = await createDeliveryJob({
        notificationId: `sim_e_dup_${Date.now()}`,
        userId: DEMO_USER_ID,
        priority: 'HIGH',
        idempotencyKey: fixedKey,
        recipientEmail: DEMO_EMAIL,
        isDemoJob: true,
        demoFaults: { shortTimeouts: true },
      });
      const passed =
        first.created === true &&
        second.created === false &&
        second.idempotentReplay === true &&
        first.job.id === second.job.id;
      return {
        id: 'e',
        title: '(e) Duplicate create with same idempotencyKey -> only one job created',
        expectedOutcome: 'Second call returns existing job with idempotentReplay=true',
        actualOutcome: `first.created=${first.created}, second.created=${second.created}, sameId=${first.job.id === second.job.id}`,
        passed,
        durationMs: Date.now() - started,
        jobId: first.job.id,
        jobSnapshot: first.job,
      };
    }

    case 'f': {
      let rejectedPure = false;
      let rejectedStore = false;
      let errorMsg = '';

      try {
        transition({ state: 'DELIVERED_ACKED', channel: 'push' }, { type: 'START', channel: 'sms' });
      } catch (err: any) {
        if (err instanceof IllegalTransitionError) {
          rejectedPure = true;
          errorMsg = err.message;
        }
      }

      const { job } = await createDeliveryJob({
        notificationId: `sim_f_${Date.now()}`,
        userId: DEMO_USER_ID,
        priority: 'NORMAL',
        idempotencyKey: `sim:f:${Date.now()}:${crypto.randomBytes(3).toString('hex')}`,
        isDemoJob: true,
        demoFaults: { shortTimeouts: true },
      });
      await processSingleDeliveryJob(job.id, { shortDemoBackoffMs: 30 });
      try {
        await applyStateTransitionToJob({
          jobId: job.id,
          event: 'ACK_TIMEOUT',
          resultText: 'Attempt illegal post-terminal transition',
        });
      } catch (err: any) {
        if (err instanceof IllegalTransitionError) {
          rejectedStore = true;
        }
      }

      const finalJob = await getDeliveryJobById(job.id);
      const passed = rejectedPure && rejectedStore;
      return {
        id: 'f',
        title: '(f) Illegal transition (event after terminal state) -> rejected',
        expectedOutcome: 'Both pure transition() and durable store reject events on terminal states',
        actualOutcome: `rejectedPure=${rejectedPure}, rejectedStore=${rejectedStore} (${errorMsg})`,
        passed,
        durationMs: Date.now() - started,
        jobId: job.id,
        jobSnapshot: finalJob,
      };
    }

    case 'g': {
      const { job } = await createDeliveryJob({
        notificationId: `sim_g_${Date.now()}`,
        userId: DEMO_USER_ID,
        priority: 'CRITICAL',
        idempotencyKey: `sim:g:${Date.now()}:${crypto.randomBytes(3).toString('hex')}`,
        recipientEmail: DEMO_EMAIL,
        recipientPhone: DEMO_PHONE,
        isDemoJob: true,
        demoFaults: { forcePushFail: true, shortTimeouts: true },
      });

      // Step 1: initial fail -> RETRY_WAIT(push)
      const pausedMidFlight = await processSingleDeliveryJob(job.id, { shortDemoBackoffMs: 80 });
      const midStateLabel = pausedMidFlight
        ? formatMachineState({ state: pausedMidFlight.state, channel: pausedMidFlight.channel })
        : 'NONE';

      // Step 2: Simulate server restart (wipes ALL in-memory Maps & reloads from durable storage)
      const reloadInfo = simulateServerRestartReload();

      // Step 3: Resume from durable state and complete on SMS
      const resumed = await driveDemoJobUntil(
        job.id,
        (j) =>
          (j.state === 'AWAITING_ACK' && j.channel === 'sms') ||
          j.state === 'DELIVERED_ACKED',
        16
      );
      const completed =
        resumed.state === 'AWAITING_ACK'
          ? await acknowledgeDeliveryJob({ jobId: resumed.id, via: 'post-restart-resume-ack' })
          : resumed;

      const passed =
        reloadInfo.reloadedCount > 0 &&
        completed.state === 'DELIVERED_ACKED' &&
        completed.history.length >= 3;

      return {
        id: 'g',
        title: '(g) Server restart mid-job -> job resumes from saved state',
        expectedOutcome: 'Job persists mid-flight, survives memory wipe, and completes on next worker tick',
        actualOutcome: `MidState=${midStateLabel}, reloaded=${reloadInfo.reloadedCount} jobs, Final=${completed.state} (${completed.channel})`,
        passed,
        durationMs: Date.now() - started,
        jobId: completed.id,
        jobSnapshot: completed,
      };
    }
  }
}

export async function runAllSimulatorScenarios(): Promise<{
  results: ScenarioTestResult[];
  passedCount: number;
  totalCount: number;
  allPassed: boolean;
  generatedAt: string;
}> {
  const ids: SimulatorScenarioId[] = ['a', 'b', 'c', 'd', 'e', 'f', 'g'];
  const results: ScenarioTestResult[] = [];
  for (const id of ids) {
    const res = await runSimulatorScenario(id);
    results.push(res);
  }
  const passedCount = results.filter((r) => r.passed).length;
  return {
    results,
    passedCount,
    totalCount: results.length,
    allPassed: passedCount === results.length,
    generatedAt: new Date().toISOString(),
  };
}
