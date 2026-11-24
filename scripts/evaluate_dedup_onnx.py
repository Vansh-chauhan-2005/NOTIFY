#!/usr/bin/env python3
"""
AegisNotify — Offline Semantic Deduplication Evaluator (Google Colab Ready)

Generates ~600 labelled notification pairs across:
  1. English semantic paraphrases (positives)
  2. Hindi / Hinglish paraphrases (positives)
  3. Entity-trap pairs (Rs 500 vs Rs 50,000, different OTPs/IDs/dates -> negatives)
  4. Negation & state-transition pairs (Server down vs recovered -> negatives)
  5. Distinct unrelated alerts (negatives)

Compares:
  - Baseline 1: Exact normalized text match
  - Baseline 2: TF-IDF cosine similarity (unigrams + bigrams)
  - Primary ML: sentence-transformers (`sentence-transformers/all-MiniLM-L6-v2`)
    matching the browser ONNX Xenova/all-MiniLM-L6-v2 model.

Sweeps threshold 0.50..0.99 (step 0.01), prints Precision / Recall / F1 / ROC-AUC,
confusion matrix, PR curve summary, and exports `dedupConfig.json`.

Usage in Google Colab:
  !pip install -q sentence-transformers scikit-learn numpy
  !python scripts/evaluate_dedup_onnx.py --out dedupConfig.json
"""

from __future__ import annotations

import argparse
import json
import math
import random
import re
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Tuple


POSITIVE_CLUSTERS: List[List[str]] = [
    [
        "Production API server is down and returning 503 errors",
        "Prod server unreachable from edge gateway",
        "Production backend API not responding to health checks",
        "Core prod API outage detected across US-East nodes",
        "Production server chal nahi raha hai 503 error aa raha hai",
        "Prod backend down hai request timeout ho rahi hai",
    ],
    [
        "Database connection pool exhausted on primary postgres cluster",
        "Primary Postgres DB out of available connections",
        "Unable to acquire database connection from primary pool",
        "Postgres pool saturation preventing new queries",
        "Database connections full ho gayi hain primary DB pe",
    ],
    [
        "High CPU utilization above 95% on worker-node-04",
        "Worker node 04 CPU load critically high over 95 percent",
        "Sustained CPU spike exceeding 95% on worker-node-04",
        "Worker-node-04 par CPU usage 95% se zyada ho gaya hai",
    ],
    [
        "TLS certificate for api.aegisnotify.io expires in 48 hours",
        "SSL cert renewal urgent for api.aegisnotify.io within 2 days",
        "HTTPS certificate on api.aegisnotify.io nearing expiry in 48h",
        "api.aegisnotify.io ka SSL certificate 48 ghante mein expire hoga",
    ],
    [
        "Stripe webhook delivery latency elevated above 12 seconds",
        "Payment webhook callbacks delayed over 12s from Stripe gateway",
        "Slow webhook responses detected on Stripe billing integration",
        "Stripe payment webhook slow chal raha hai 12s delay",
    ],
    [
        "Redis memory usage reached 92% capacity on session cache",
        "Session Redis cache nearly full at 92 percent RAM",
        "High memory pressure on Redis cache cluster (92% used)",
        "Redis cache memory 92% bhar gayi hai",
    ],
    [
        "Kubernetes pod crashloopbackoff in billing-service",
        "Billing service pods repeatedly crashing in k8s cluster",
        "CrashLoopBackOff alert for billing-service deployment",
    ],
    [
        "Disk space critically low on /var/log volume (96% used)",
        "Storage almost full at 96 percent on /var/log partition",
        "Log disk partition /var/log has only 4% free space left",
    ],
]

ENTITY_TRAP_PAIRS: List[Tuple[str, str]] = [
    ("Payment debited Rs 500 at Metro Store", "Payment debited Rs 50,000 at Metro Store"),
    ("Your login OTP code is 841290", "Your login OTP code is 192045"),
    ("Order #ORD-10421 shipped via Express", "Order #ORD-99812 shipped via Express"),
    ("Invoice #INV-2026-01 overdue for $120.00", "Invoice #INV-2026-88 overdue for $9,450.00"),
    ("Transfer of INR 1,200 to account ending 4421", "Transfer of INR 85,000 to account ending 9910"),
    ("Security login from IP 10.20.30.40", "Security login from IP 185.220.101.9"),
    ("Meeting scheduled for 2026-11-23 at 10:00", "Meeting scheduled for 2026-12-04 at 16:30"),
    ("Aapka OTP 445566 hai kisi ke saath share na karein", "Aapka OTP 998811 hai kisi ke saath share na karein"),
]

NEGATION_TRAP_PAIRS: List[Tuple[str, str]] = [
    ("Production API server is down", "Production API server is back up and recovered"),
    ("Database outage resolved — services healthy", "Database outage active — services unreachable"),
    ("Deployment #412 failed during rollout", "Deployment #412 succeeded cleanly"),
    ("Payment transaction failed for order #882", "Payment transaction successful for order #882"),
    ("Login attempt blocked by firewall", "Login attempt allowed after MFA verification"),
    ("Redis cache unreachable from worker", "Redis cache connection restored and healthy"),
    ("Server band hai abhi", "Server wapas chalu ho gaya hai resolved"),
    ("Webhook pipeline stopped with errors", "Webhook pipeline resumed without errors"),
]

UNRELATED_POOL: List[str] = [
    "Weekly engineering standup notes uploaded to Drive",
    "Flash sale 40% off annual workspace plans this weekend",
    "New PR #419 awaiting your code review in github",
    "Your monthly billing statement is ready for download",
    "Reminder: security awareness training due Friday",
    "Slack mention from @ananya in #incident-triage",
    "Jira ticket AEGIS-304 moved to In Progress",
    "CI pipeline build #902 passed all unit tests",
    "New device Firefox on Linux signed in at 09:14 UTC",
    "Ed25519 signing key rotated cleanly in transparency log",
]


def normalize_text(text: str) -> str:
    text = text.lower().strip()
    text = re.sub(r"[\u200b-\u200d\ufeff]", "", text)
    text = re.sub(r"\s+", " ", text)
    return text


def build_dataset(target_pairs: int = 600, seed: int = 42) -> List[Dict[str, object]]:
    rng = random.Random(seed)
    pairs: List[Dict[str, object]] = []

    # ~240 positive semantic duplicate pairs (within cluster)
    pos_candidates: List[Tuple[str, str, str]] = []
    for c_idx, cluster in enumerate(POSITIVE_CLUSTERS):
        for i in range(len(cluster)):
            for j in range(i + 1, len(cluster)):
                tag = "hinglish" if any(w in cluster[i] + cluster[j] for w in ("hai", "ho ", "se ", "mein", "par")) else "english"
                pos_candidates.append((cluster[i], cluster[j], f"pos_{tag}_c{c_idx}"))

    while len([p for p in pairs if p["label"] == 1]) < 240:
        a, b, group = rng.choice(pos_candidates)
        pairs.append({"a": a, "b": b, "label": 1, "category": group})

    # ~120 entity traps (hard negatives)
    for idx in range(120):
        a, b = ENTITY_TRAP_PAIRS[idx % len(ENTITY_TRAP_PAIRS)]
        pairs.append({"a": a, "b": b, "label": 0, "category": "neg_entity_trap"})

    # ~120 negation/state traps (hard negatives)
    for idx in range(120):
        a, b = NEGATION_TRAP_PAIRS[idx % len(NEGATION_TRAP_PAIRS)]
        pairs.append({"a": a, "b": b, "label": 0, "category": "neg_state_trap"})

    # ~120 cross-cluster / unrelated pairs (negatives)
    while len(pairs) < target_pairs:
        c1, c2 = rng.sample(range(len(POSITIVE_CLUSTERS)), 2)
        if rng.random() < 0.5:
            a = rng.choice(POSITIVE_CLUSTERS[c1])
            b = rng.choice(POSITIVE_CLUSTERS[c2])
        else:
            a = rng.choice(POSITIVE_CLUSTERS[c1])
            b = rng.choice(UNRELATED_POOL)
        pairs.append({"a": a, "b": b, "label": 0, "category": "neg_unrelated"})

    rng.shuffle(pairs)
    return pairs[:target_pairs]


def tokenize_ngrams(text: str) -> List[str]:
    clean = re.sub(r"[^\w\s]", " ", normalize_text(text))
    words = [w for w in clean.split() if w]
    bigrams = [f"{words[i]}_{words[i + 1]}" for i in range(len(words) - 1)]
    return words + bigrams


def compute_tfidf_scores(pairs: List[Dict[str, object]]) -> List[float]:
    docs = [tokenize_ngrams(str(p["a"])) for p in pairs] + [tokenize_ngrams(str(p["b"])) for p in pairs]
    df: Counter[str] = Counter()
    for d in docs:
        for tok in set(d):
            df[tok] += 1
    n_docs = len(docs)

    def vec(tokens: List[str]) -> Dict[str, float]:
        tf = Counter(tokens)
        total = max(1, len(tokens))
        v: Dict[str, float] = {}
        for tok, cnt in tf.items():
            idf = math.log((1 + n_docs) / (1 + df[tok])) + 1.0
            v[tok] = (cnt / total) * idf
        norm = math.sqrt(sum(val * val for val in v.values())) or 1.0
        return {k: val / norm for k, val in v.items()}

    scores: List[float] = []
    for p in pairs:
        va = vec(tokenize_ngrams(str(p["a"])))
        vb = vec(tokenize_ngrams(str(p["b"])))
        dot = sum(val * vb.get(tok, 0.0) for tok, val in va.items())
        scores.append(max(0.0, min(1.0, dot)))
    return scores


def compute_exact_scores(pairs: List[Dict[str, object]]) -> List[float]:
    return [1.0 if normalize_text(str(p["a"])) == normalize_text(str(p["b"])) else 0.0 for p in pairs]


def has_entity_conflict(a: str, b: str) -> bool:
    num_pat = re.compile(r"\b(?:rs\.?|inr|usd|\$)?\s*\d[\d,]*(?:\.\d+)?\b", re.I)
    id_pat = re.compile(r"#?[A-Z]{2,}-\d+|\b\d{4,8}\b")
    nums_a = {re.sub(r"[,\s]", "", m.lower()) for m in num_pat.findall(a)}
    nums_b = {re.sub(r"[,\s]", "", m.lower()) for m in num_pat.findall(b)}
    ids_a = {m.lower() for m in id_pat.findall(a)}
    ids_b = {m.lower() for m in id_pat.findall(b)}
    if nums_a and nums_b and nums_a != nums_b:
        return True
    if ids_a and ids_b and ids_a != ids_b:
        return True
    return False


def has_negation_conflict(a: str, b: str) -> bool:
    down_words = {"down", "outage", "unreachable", "failed", "blocked", "stopped", "band"}
    up_words = {"up", "recovered", "resolved", "restored", "healthy", "succeeded", "successful", "allowed", "resumed", "chalu"}
    wa = set(re.findall(r"[a-z]+", normalize_text(a)))
    wb = set(re.findall(r"[a-z]+", normalize_text(b)))
    a_down, a_up = bool(wa & down_words), bool(wa & up_words)
    b_down, b_up = bool(wb & down_words), bool(wb & up_words)
    return (a_down and b_up) or (a_up and b_down)


def eval_at_threshold(labels: List[int], scores: List[float], threshold: float, pairs=None, apply_guards: bool = False):
    tp = fp = tn = fn = 0
    for idx, (y, s) in enumerate(zip(labels, scores)):
        pred = 1 if s >= threshold else 0
        if pred == 1 and apply_guards and pairs is not None:
            a = str(pairs[idx]["a"])
            b = str(pairs[idx]["b"])
            if has_entity_conflict(a, b) or has_negation_conflict(a, b):
                pred = 0
        if pred == 1 and y == 1:
            tp += 1
        elif pred == 1 and y == 0:
            fp += 1
        elif pred == 0 and y == 0:
            tn += 1
        else:
            fn += 1

    precision = tp / (tp + fp) if (tp + fp) > 0 else 1.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) > 0 else 0.0
    accuracy = (tp + tn) / max(1, tp + fp + tn + fn)
    return {
        "threshold": round(threshold, 2),
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(f1, 4),
        "accuracy": round(accuracy, 4),
        "confusionMatrix": [[tn, fp], [fn, tp]],
    }


def compute_roc_auc(labels: List[int], scores: List[float]) -> float:
    pos = [s for y, s in zip(labels, scores) if y == 1]
    neg = [s for y, s in zip(labels, scores) if y == 0]
    if not pos or not neg:
        return 0.5
    wins = 0.0
    for ps in pos:
        for ns in neg:
            if ps > ns:
                wins += 1.0
            elif ps == ns:
                wins += 0.5
    return round(wins / (len(pos) * len(neg)), 4)


def main():
    parser = argparse.ArgumentParser(description="Evaluate AegisNotify Semantic Deduplication ONNX vs baselines")
    parser.add_argument("--out", default="dedupConfig.json", help="Output path for exported dedupConfig.json")
    parser.add_argument("--pairs", type=int, default=600, help="Number of synthetic evaluation pairs")
    parser.add_argument("--use-onnx", action="store_true", help="Run sentence-transformers all-MiniLM-L6-v2 if installed")
    args = parser.parse_args()

    pairs = build_dataset(args.pairs)
    labels = [int(p["label"]) for p in pairs]

    exact_scores = compute_exact_scores(pairs)
    tfidf_scores = compute_tfidf_scores(pairs)

    def apply_guard_mask(raw_scores: List[float]) -> List[float]:
        masked: List[float] = []
        for idx, sc in enumerate(raw_scores):
            a = str(pairs[idx]["a"])
            b = str(pairs[idx]["b"])
            if has_entity_conflict(a, b) or has_negation_conflict(a, b):
                masked.append(0.0)
            else:
                masked.append(sc)
        return masked

    model_mode = "tfidf_baseline_only"
    semantic_scores = tfidf_scores

    try:
        from sentence_transformers import SentenceTransformer  # type: ignore
        import numpy as np  # type: ignore

        print("Loading sentence-transformers/all-MiniLM-L6-v2 ...")
        model = SentenceTransformer("sentence-transformers/all-MiniLM-L6-v2")
        texts_a = [normalize_text(str(p["a"])) for p in pairs]
        texts_b = [normalize_text(str(p["b"])) for p in pairs]
        emb_a = model.encode(texts_a, normalize_embeddings=True, batch_size=64, show_progress_bar=False)
        emb_b = model.encode(texts_b, normalize_embeddings=True, batch_size=64, show_progress_bar=False)
        semantic_scores = [float(np.clip(np.dot(emb_a[i], emb_b[i]), -1.0, 1.0)) for i in range(len(pairs))]
        model_mode = "sentence-transformers/all-MiniLM-L6-v2"
    except Exception as exc:
        if args.use_onnx:
            raise
        print(f"sentence-transformers unavailable locally ({exc}); reporting TF-IDF evaluation sweep.")

    guarded_semantic_scores = apply_guard_mask(semantic_scores)
    guarded_tfidf_scores = apply_guard_mask(tfidf_scores)
    guarded_exact_scores = apply_guard_mask(exact_scores)

    sweep = []
    best_row = None
    for step in range(50, 100):
        th = step / 100.0
        row = eval_at_threshold(labels, semantic_scores, th, pairs=pairs, apply_guards=True)
        sweep.append(row)
        if best_row is None or row["f1"] > best_row["f1"]:
            best_row = row

    exact_eval = eval_at_threshold(labels, exact_scores, 0.99, pairs=pairs, apply_guards=True)
    tfidf_eval = eval_at_threshold(labels, tfidf_scores, 0.50, pairs=pairs, apply_guards=True)
    roc_auc = compute_roc_auc(labels, guarded_semantic_scores)

    recommended_merge = (
        max(0.84, min(0.92, float(best_row["threshold"])))
        if model_mode == "sentence-transformers/all-MiniLM-L6-v2" and best_row
        else 0.88
    )
    recommended_review = round(max(0.70, recommended_merge - 0.10), 2)

    pr_curve = [
        {
            "threshold": r["threshold"],
            "precision": r["precision"],
            "recall": r["recall"],
            "f1": r["f1"],
        }
        for r in sweep
        if round(r["threshold"] * 100) % 5 == 0 or r["threshold"] in (0.78, 0.88)
    ]

    config = {
        "version": "1.0.0-minilm-dedup",
        "generatedAt": datetime.now(timezone.utc).isoformat(),
        "modelId": "Xenova/all-MiniLM-L6-v2",
        "quantized": True,
        "embeddingDim": 384,
        "maxTokens": 256,
        "mergeThreshold": recommended_merge,
        "reviewThreshold": recommended_review,
        "userThresholdMin": 0.80,
        "userThresholdMax": 0.95,
        "windowMinutes": 30,
        "maxWindowItems": 500,
        "maxThreadsPerSourcePerHour": 20,
        "minHashPermutations": 32,
        "minHashShingleSize": 3,
        "minHashThreshold": 0.68,
        "tfidfFallbackMergeThreshold": 0.74,
        "tfidfFallbackReviewThreshold": 0.60,
        "neverMergeCategories": ["security", "otp", "auth", "provenance"],
        "evaluation": {
            "source": "synthetic_colab_eval_set",
            "evaluator": model_mode,
            "pairCount": len(pairs),
            "positivePairs": sum(labels),
            "negativePairs": len(pairs) - sum(labels),
            "rocAuc": roc_auc,
            "atRecommendedThreshold": eval_at_threshold(
                labels, semantic_scores, recommended_merge, pairs=pairs, apply_guards=True
            ),
            "bestF1Threshold": best_row,
            "prCurve": pr_curve,
            "methodComparison": [
                {"method": "Exact Normalized SHA-256 + Guards", **exact_eval, "rocAuc": compute_roc_auc(labels, guarded_exact_scores)},
                {"method": "TF-IDF Cosine + Safety Guards", **tfidf_eval, "rocAuc": compute_roc_auc(labels, guarded_tfidf_scores)},
                {
                    "method": f"{model_mode} + Safety Guards",
                    **eval_at_threshold(labels, semantic_scores, recommended_merge, pairs=pairs, apply_guards=True),
                    "rocAuc": roc_auc,
                },
            ],
        },
        "modelCard": {
            "modelName": "Xenova/all-MiniLM-L6-v2 (INT8/Quantized ONNX)",
            "embeddingDimensions": 384,
            "maxSequenceTokens": 256,
            "approxDownloadMb": 23,
            "intendedUse": "On-device semantic similarity grouping of related operational notifications inside a 30-minute RAM sliding window.",
            "outOfScopeAndHonesty": [
                "Similarity heuristic only — paraphrases, abbreviations, or multilingual phrasing can still miss or collide.",
                "Never merges CRITICAL/security/OTP/login/provenance-failure alerts or notifications with conflicting numbers, IDs, dates, or opposite state words.",
                "Evaluation numbers come from the 600-pair offline synthetic benchmark in scripts/evaluate_dedup_onnx.py, NOT live production traffic.",
                "Plaintext and embedding float vectors stay strictly in device volatile RAM and are never persisted or logged.",
            ],
        },
    }

    out_path = Path(args.out)
    out_path.write_text(json.dumps(config, indent=2) + "\n", encoding="utf-8")
    print(f"Wrote {out_path} | ROC-AUC={roc_auc} | Merge={recommended_merge} | Review={recommended_review}")


if __name__ == "__main__":
    main()
