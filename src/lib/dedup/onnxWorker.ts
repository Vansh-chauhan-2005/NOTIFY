/// <reference lib="webworker" />

import { l2Normalize } from './similarity.js';

interface WorkerInitMessage {
  type: 'INIT';
  modelId: string;
  preferWebGpu?: boolean;
}

interface WorkerEmbedMessage {
  type: 'EMBED';
  requestId: string;
  text: string;
  modelId: string;
}

type IncomingWorkerMessage = WorkerInitMessage | WorkerEmbedMessage;

let extractor: ((text: string, opts?: Record<string, unknown>) => Promise<any>) | null = null;
let initPromise: Promise<boolean> | null = null;
let activeBackend: 'wasm' | 'webgpu' = 'wasm';
let initFailedReason: string | null = null;

async function detectBackend(preferWebGpu: boolean): Promise<'wasm' | 'webgpu'> {
  if (!preferWebGpu) return 'wasm';
  try {
    const nav = typeof navigator !== 'undefined' ? (navigator as any) : null;
    if (nav && nav.gpu && typeof nav.gpu.requestAdapter === 'function') {
      const adapter = await nav.gpu.requestAdapter();
      if (adapter) return 'webgpu';
    }
  } catch {
    // Fall back safely to WASM
  }
  return 'wasm';
}

async function ensureModelLoaded(modelId: string, preferWebGpu = false): Promise<boolean> {
  if (extractor) return true;
  if (initFailedReason) return false;
  if (initPromise) return initPromise;

  initPromise = (async () => {
    try {
      const transformersCdnUrl: string =
        'https://cdn.jsdelivr.net/npm/@huggingface/transformers@4.3.2/dist/transformers.web.min.js';
      const transformers = await import(/* @vite-ignore */ transformersCdnUrl);
      const { pipeline, env } = transformers as any;

      if (env) {
        env.useBrowserCache = true;
        env.allowLocalModels = true;
        env.localModelPath = '/models/';
        env.allowRemoteModels = true;
        if (env.backends?.onnx?.wasm) {
          env.backends.onnx.wasm.numThreads = 1;
        }
      }

      activeBackend = await detectBackend(preferWebGpu);

      const loadTask = pipeline('feature-extraction', modelId, {
        dtype: 'q8',
        device: activeBackend,
        progress_callback: (info: any) => {
          if (!info) return;
          const progress =
            typeof info.progress === 'number'
              ? Math.max(0, Math.min(100, Math.round(info.progress)))
              : undefined;
          self.postMessage({
            type: 'PROGRESS',
            status: String(info.status || 'loading'),
            file: typeof info.file === 'string' ? info.file : undefined,
            progress,
            backend: activeBackend,
          });
        },
      });

      // Protect against silent network hang in offline/firewalled sandboxes
      const timeoutPromise = new Promise<null>((resolve) => {
        setTimeout(() => resolve(null), 15000);
      });

      const loaded = await Promise.race([loadTask, timeoutPromise]);
      if (!loaded) {
        initFailedReason = 'Model download timed out after 15s; using TF-IDF lightweight mode.';
        self.postMessage({
          type: 'FALLBACK',
          reason: initFailedReason,
        });
        return false;
      }

      extractor = loaded;
      self.postMessage({
        type: 'READY',
        backend: activeBackend,
        modelId,
      });
      return true;
    } catch (err: any) {
      initFailedReason = err?.message || 'Unable to load ONNX runtime in browser.';
      self.postMessage({
        type: 'FALLBACK',
        reason: initFailedReason,
      });
      return false;
    }
  })();

  return initPromise;
}

self.onmessage = async (event: MessageEvent<IncomingWorkerMessage>) => {
  const msg = event.data;
  if (!msg) return;

  if (msg.type === 'INIT') {
    const ok = await ensureModelLoaded(msg.modelId, Boolean(msg.preferWebGpu));
    if (!ok) {
      self.postMessage({
        type: 'FALLBACK',
        reason: initFailedReason || 'Switched to TF-IDF lightweight mode.',
      });
    }
    return;
  }

  if (msg.type === 'EMBED') {
    try {
      const ok = await ensureModelLoaded(msg.modelId, false);
      if (!ok || !extractor) {
        self.postMessage({
          type: 'EMBED_RESULT',
          requestId: msg.requestId,
          ok: false,
          embedding: null,
          backend: activeBackend,
          reason: initFailedReason || 'ONNX model unavailable; using TF-IDF lightweight mode.',
        });
        return;
      }

      const output = await extractor(msg.text, {
        pooling: 'mean',
        normalize: true,
      });

      const raw = output?.data ? Array.from(output.data as ArrayLike<number>) : [];
      const embedding = raw.length > 0 ? l2Normalize(raw.slice(0, 384)) : null;

      self.postMessage({
        type: 'EMBED_RESULT',
        requestId: msg.requestId,
        ok: Boolean(embedding),
        embedding,
        backend: activeBackend,
      });
    } catch (err: any) {
      self.postMessage({
        type: 'EMBED_RESULT',
        requestId: msg.requestId,
        ok: false,
        embedding: null,
        backend: activeBackend,
        reason: err?.message || 'Worker embedding error; falling back to TF-IDF lightweight mode.',
      });
    }
  }
};
