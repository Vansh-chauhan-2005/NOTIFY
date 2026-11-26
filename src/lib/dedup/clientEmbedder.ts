'use client';

import { DEFAULT_DEDUP_CONFIG } from './config.js';
import { preprocessNotificationText } from './preprocess.js';
import { buildTfIdfSparseVector } from './tfidf.js';
import type { EmbedderBenchmarkResult } from './types.js';

export type ClientEmbedderStatus =
  | 'idle'
  | 'loading'
  | 'ready'
  | 'lightweight_fallback';

export interface ClientEmbedderSnapshot {
  status: ClientEmbedderStatus;
  backend: 'wasm' | 'webgpu' | 'cpu_ts';
  progressPercent: number;
  loadingFile: string | null;
  approxDownloadMb: number;
  modelId: string;
  lastLoadMs: number | null;
  cachedInBrowser: boolean;
  fallbackReason: string | null;
}

type Listener = (snapshot: ClientEmbedderSnapshot) => void;

const BENCHMARK_SAMPLES = [
  'Production API server is down and returning 503 errors',
  'Prod server unreachable from edge gateway',
  'Database connection pool exhausted on primary cluster',
  'Worker node 04 CPU spike above 95 percent',
  'TLS certificate for api.aegisnotify.io expires in 48 hours',
  'Stripe payment webhook callbacks delayed over 12s',
  'Production server chal nahi raha hai timeout ho raha hai',
  'Payment debited Rs 500 at Metro Store',
  'Payment debited Rs 50,000 at Metro Store',
  'Production API server is back up and recovered',
  'Redis memory usage reached 92% capacity',
  'Kubernetes pod crashloopbackoff in billing-service',
];

let workerInstance: Worker | null = null;
let loadStartMs: number | null = null;
let telemetryReportedReady = false;
let telemetryReportedFallback = false;

const listeners = new Set<Listener>();
const pendingRequests = new Map<
  string,
  {
    resolve: (res: { embedding: number[] | null; mode: 'onnx_minilm' | 'tfidf_lightweight' }) => void;
    timer: ReturnType<typeof setTimeout>;
  }
>();

let state: ClientEmbedderSnapshot = {
  status: 'idle',
  backend: 'wasm',
  progressPercent: 0,
  loadingFile: null,
  approxDownloadMb: DEFAULT_DEDUP_CONFIG.modelCard.approxDownloadMb || 23,
  modelId: DEFAULT_DEDUP_CONFIG.modelId || 'Xenova/all-MiniLM-L6-v2',
  lastLoadMs: null,
  cachedInBrowser: false,
  fallbackReason: null,
};

function notifyListeners() {
  const snap = { ...state };
  for (const fn of listeners) {
    try {
      fn(snap);
    } catch {
      // ignore listener errors
    }
  }
}

async function checkBrowserCacheForModel(): Promise<boolean> {
  if (typeof window === 'undefined' || !('caches' in window)) return false;
  try {
    const keys = await window.caches.keys();
    return keys.some((k) => k.toLowerCase().includes('transformers'));
  } catch {
    return false;
  }
}

function reportClientTelemetryOnce(eventType: 'DEDUP_MODEL_LOADED' | 'DEDUP_FALLBACK_USED', details: string) {
  if (typeof window === 'undefined') return;
  if (eventType === 'DEDUP_MODEL_LOADED' && telemetryReportedReady) return;
  if (eventType === 'DEDUP_FALLBACK_USED' && telemetryReportedFallback) return;
  if (eventType === 'DEDUP_MODEL_LOADED') telemetryReportedReady = true;
  if (eventType === 'DEDUP_FALLBACK_USED') telemetryReportedFallback = true;

  const token = window.localStorage.getItem('aegis_auth_token');
  void fetch('/api/v1/dedup/feedback', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
    },
    body: JSON.stringify({
      clientSignal: eventType,
      details,
    }),
  }).catch(() => {
    // non-fatal
  });
}

function ensureWorker(): Worker | null {
  if (typeof window === 'undefined' || typeof Worker === 'undefined') {
    return null;
  }
  if (state.status === 'lightweight_fallback') {
    return null;
  }
  if (workerInstance) return workerInstance;

  try {
    workerInstance = new Worker(new URL('./onnxWorker.ts', import.meta.url), {
      type: 'module',
    });

    workerInstance.onmessage = (ev: MessageEvent<any>) => {
      const data = ev.data;
      if (!data) return;

      if (data.type === 'PROGRESS') {
        state = {
          ...state,
          status: 'loading',
          backend: data.backend === 'webgpu' ? 'webgpu' : 'wasm',
          progressPercent:
            typeof data.progress === 'number' ? data.progress : state.progressPercent,
          loadingFile: typeof data.file === 'string' ? data.file : state.loadingFile,
        };
        notifyListeners();
        return;
      }

      if (data.type === 'READY') {
        const loadElapsed = loadStartMs ? Math.round(performance.now() - loadStartMs) : null;
        void checkBrowserCacheForModel().then((cached) => {
          state = {
            ...state,
            status: 'ready',
            backend: data.backend === 'webgpu' ? 'webgpu' : 'wasm',
            progressPercent: 100,
            loadingFile: null,
            lastLoadMs: loadElapsed,
            cachedInBrowser: cached,
            fallbackReason: null,
          };
          notifyListeners();
        });
        reportClientTelemetryOnce(
          'DEDUP_MODEL_LOADED',
          `Browser ONNX ${state.modelId} loaded via ${data.backend || 'wasm'}${loadElapsed ? ` in ${loadElapsed}ms` : ''}.`
        );
        return;
      }

      if (data.type === 'FALLBACK') {
        const reason = String(data.reason || 'Switched to TF-IDF lightweight mode.');
        state = {
          ...state,
          status: 'lightweight_fallback',
          backend: 'cpu_ts',
          loadingFile: null,
          fallbackReason: reason,
        };
        notifyListeners();
        for (const [reqId, pending] of pendingRequests.entries()) {
          clearTimeout(pending.timer);
          pending.resolve({ embedding: null, mode: 'tfidf_lightweight' });
          pendingRequests.delete(reqId);
        }
        reportClientTelemetryOnce(
          'DEDUP_FALLBACK_USED',
          `Lightweight TF-IDF fallback activated: ${reason}`
        );
        return;
      }

      if (data.type === 'EMBED_RESULT') {
        const pending = pendingRequests.get(data.requestId);
        if (!pending) return;
        clearTimeout(pending.timer);
        pendingRequests.delete(data.requestId);
        if (data.ok && Array.isArray(data.embedding)) {
          pending.resolve({
            embedding: data.embedding,
            mode: 'onnx_minilm',
          });
        } else {
          if (data.reason && state.status !== 'lightweight_fallback') {
            state = {
              ...state,
              status: 'lightweight_fallback',
              backend: 'cpu_ts',
              fallbackReason: String(data.reason),
            };
            notifyListeners();
            reportClientTelemetryOnce(
              'DEDUP_FALLBACK_USED',
              `Lightweight TF-IDF fallback activated: ${String(data.reason)}`
            );
          }
          pending.resolve({ embedding: null, mode: 'tfidf_lightweight' });
        }
      }
    };

    workerInstance.onerror = (err) => {
      err?.preventDefault?.();
      state = {
        ...state,
        status: 'lightweight_fallback',
        backend: 'cpu_ts',
        fallbackReason: err?.message || 'ONNX worker failed; using TF-IDF lightweight mode.',
      };
      notifyListeners();
      for (const [reqId, pending] of pendingRequests.entries()) {
        clearTimeout(pending.timer);
        pending.resolve({ embedding: null, mode: 'tfidf_lightweight' });
        pendingRequests.delete(reqId);
      }
    };

    return workerInstance;
  } catch (err: any) {
    state = {
      ...state,
      status: 'lightweight_fallback',
      backend: 'cpu_ts',
      fallbackReason: err?.message || 'Web Worker unavailable; using TF-IDF lightweight mode.',
    };
    notifyListeners();
    return null;
  }
}

export function getEmbedderSnapshot(): ClientEmbedderSnapshot {
  return { ...state };
}

export function subscribeEmbedderSnapshot(listener: Listener): () => void {
  listeners.add(listener);
  listener({ ...state });
  return () => {
    listeners.delete(listener);
  };
}

export function prewarmOnnxEmbedder(preferWebGpu = false): void {
  if (typeof window === 'undefined') return;
  if (state.status === 'ready' || state.status === 'loading') return;

  // Reset prior fallback if user explicitly retries loading ONNX model
  if (state.status === 'lightweight_fallback') {
    disposeClientEmbedder();
    state = {
      ...state,
      status: 'loading',
      backend: 'wasm',
      progressPercent: 0,
      fallbackReason: null,
    };
  } else {
    state = {
      ...state,
      status: 'loading',
      progressPercent: 5,
    };
  }
  loadStartMs = performance.now();
  notifyListeners();

  const worker = ensureWorker();
  if (!worker) return;
  worker.postMessage({
    type: 'INIT',
    modelId: state.modelId,
    preferWebGpu,
  });
}

export async function embedTextInBrowser(
  rawOrNormalizedText: string
): Promise<{ embedding: number[] | null; mode: 'onnx_minilm' | 'tfidf_lightweight' }> {
  if (typeof window === 'undefined' || state.status === 'lightweight_fallback') {
    return { embedding: null, mode: 'tfidf_lightweight' };
  }

  const worker = ensureWorker();
  if (!worker) {
    return { embedding: null, mode: 'tfidf_lightweight' };
  }

  if (state.status === 'idle') {
    loadStartMs = performance.now();
    state = { ...state, status: 'loading', progressPercent: 5 };
    notifyListeners();
  }

  const clean = preprocessNotificationText(rawOrNormalizedText, DEFAULT_DEDUP_CONFIG.maxTokens)
    .normalizedText;
  const requestId = `emb_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`;

  return await new Promise((resolve) => {
    const timer = setTimeout(() => {
      pendingRequests.delete(requestId);
      resolve({ embedding: null, mode: 'tfidf_lightweight' });
    }, 17000);

    pendingRequests.set(requestId, { resolve, timer });
    worker.postMessage({
      type: 'EMBED',
      requestId,
      text: clean,
      modelId: state.modelId,
    });
  });
}

export async function benchmarkClientEmbedder(): Promise<EmbedderBenchmarkResult> {
  const startAll = performance.now();
  let mode: 'onnx_minilm' | 'tfidf_lightweight' = 'tfidf_lightweight';

  const t0 = performance.now();
  if (state.status !== 'lightweight_fallback') {
    const first = await embedTextInBrowser(BENCHMARK_SAMPLES[0]);
    mode = first.mode;
  }
  const loadElapsed = state.lastLoadMs ?? Math.round(performance.now() - t0);

  const sampleStart = performance.now();
  for (let i = 0; i < BENCHMARK_SAMPLES.length; i++) {
    if (mode === 'onnx_minilm') {
      const r = await embedTextInBrowser(BENCHMARK_SAMPLES[i]);
      mode = r.mode;
    } else {
      const norm = preprocessNotificationText(BENCHMARK_SAMPLES[i]).normalizedText;
      buildTfIdfSparseVector(norm, BENCHMARK_SAMPLES);
    }
  }
  const totalSampleMs = Math.max(1, performance.now() - sampleStart);
  const avgEmbedMs = Number((totalSampleMs / BENCHMARK_SAMPLES.length).toFixed(2));
  const throughputPerSec = Number(((BENCHMARK_SAMPLES.length / totalSampleMs) * 1000).toFixed(1));

  const perfAny = typeof performance !== 'undefined' ? (performance as any) : null;
  const heapMb = perfAny?.memory?.usedJSHeapSize
    ? Number((perfAny.memory.usedJSHeapSize / (1024 * 1024)).toFixed(1))
    : mode === 'onnx_minilm'
    ? 48.0
    : 2.4;

  const cached = await checkBrowserCacheForModel();
  void startAll;

  return {
    mode,
    backend: mode === 'onnx_minilm' ? (state.backend === 'webgpu' ? 'webgpu' : 'wasm') : 'cpu_ts',
    modelLoadMs: loadElapsed,
    samplesTested: BENCHMARK_SAMPLES.length,
    avgEmbedMs,
    throughputPerSec,
    estimatedRamMb: heapMb,
    cachedInBrowser: cached,
  };
}

export function disposeClientEmbedder(): void {
  if (workerInstance) {
    workerInstance.terminate();
    workerInstance = null;
  }
  for (const [reqId, pending] of pendingRequests.entries()) {
    clearTimeout(pending.timer);
    pending.resolve({ embedding: null, mode: 'tfidf_lightweight' });
    pendingRequests.delete(reqId);
  }
  state = {
    ...state,
    status: 'idle',
    progressPercent: 0,
    loadingFile: null,
  };
  notifyListeners();
}
