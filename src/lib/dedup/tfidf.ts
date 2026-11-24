import { preprocessNotificationText } from './preprocess.js';

function tokenizeTfIdfFeatures(text: string): string[] {
  const { tokens } = preprocessNotificationText(text, 256);
  const features: string[] = [];
  for (let i = 0; i < tokens.length; i++) {
    const tok = tokens[i].replace(/^[^\p{L}\p{N}]+|[^\p{L}\p{N}]+$/gu, '');
    if (!tok) continue;
    features.push(`w:${tok}`);
    if (tok.length >= 4) {
      for (let j = 0; j <= tok.length - 3; j++) {
        features.push(`c:${tok.slice(j, j + 3)}`);
      }
    }
    if (i + 1 < tokens.length) {
      const next = tokens[i + 1].replace(/^[^\p{L}\p{N}]+|[^\p{L}\p{N}]+$/gu, '');
      if (next) features.push(`b:${tok}_${next}`);
    }
  }
  return features;
}

export function buildTfIdfSparseVector(
  text: string,
  corpusTexts: string[] = []
): Record<string, number> {
  const feats = tokenizeTfIdfFeatures(text);
  if (feats.length === 0) return {};

  const docCount = Math.max(2, corpusTexts.length + 1);
  const docFreq = new Map<string, number>();

  for (const doc of corpusTexts) {
    const uniqueDocFeats = new Set(tokenizeTfIdfFeatures(doc));
    for (const f of uniqueDocFeats) {
      docFreq.set(f, (docFreq.get(f) || 0) + 1);
    }
  }

  const tf = new Map<string, number>();
  for (const f of feats) {
    tf.set(f, (tf.get(f) || 0) + 1);
  }

  const rawVec: Record<string, number> = {};
  let normSq = 0;
  for (const [feat, count] of tf.entries()) {
    const df = docFreq.get(feat) || 0;
    const idf = Math.log((1 + docCount) / (1 + df)) + 1;
    const weight = (count / feats.length) * idf;
    rawVec[feat] = weight;
    normSq += weight * weight;
  }

  const norm = Math.sqrt(normSq);
  if (norm === 0) return rawVec;
  for (const key of Object.keys(rawVec)) {
    rawVec[key] = rawVec[key] / norm;
  }
  return rawVec;
}

export function sparseCosineSimilarity(
  a: Record<string, number>,
  b: Record<string, number>
): number {
  const keysA = Object.keys(a);
  if (keysA.length === 0) return 0;
  let dot = 0;
  for (const key of keysA) {
    const bv = b[key];
    if (typeof bv === 'number') {
      dot += a[key] * bv;
    }
  }
  return Math.max(0, Math.min(1, Number(dot.toFixed(6))));
}

export function computeTfIdfPairSimilarity(
  textA: string,
  textB: string,
  corpusTexts: string[] = []
): number {
  const vecA = buildTfIdfSparseVector(textA, [...corpusTexts, textB]);
  const vecB = buildTfIdfSparseVector(textB, [...corpusTexts, textA]);
  return sparseCosineSimilarity(vecA, vecB);
}
