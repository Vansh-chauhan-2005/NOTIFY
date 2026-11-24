#!/usr/bin/env python3
"""
AegisNotify — Offline Dynamic Sigmoid Priority Model Trainer (Colab-Ready)

This script builds a synthetic 3,000-notification training corpus across 14 normalized
numeric features in [0, 1], fits a calibrated L2-regularized LogisticRegression model
with 5-fold cross-validation + 80/20 stratified train/test split, evaluates Accuracy,
Precision, Recall, F1, ROC-AUC, Confusion Matrix, and 10-bin Calibration Reliability,
and exports the weights + model card to `src/lib/priority/defaultWeights.json`.

Run in Google Colab or any Python environment with numpy + scikit-learn:
  pip install numpy scikit-learn
  python scripts/train_priority_model.py --out src/lib/priority/defaultWeights.json
"""

import argparse
import json
import math
from datetime import datetime, timezone
from pathlib import Path

import numpy as np
from sklearn.calibration import calibration_curve
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.model_selection import StratifiedKFold, cross_val_score, train_test_split

FEATURE_NAMES = [
    "textScore",
    "keywordUrgency",
    "senderTrust",
    "sourceReliability",
    "category_security",
    "category_finance",
    "category_work",
    "category_social",
    "category_promo",
    "ageFactor",
    "userContext",
    "repetition",
    "userAffinity",
    "senderClaimedPriority",
]


def generate_synthetic_dataset(n_samples: int = 3000, seed: int = 42):
    rng = np.random.default_rng(seed)

    # Category distribution: security (16%), finance (15%), work (27%), social (22%), promo (20%)
    cat_probs = [0.16, 0.15, 0.27, 0.22, 0.20]
    categories = rng.choice(5, size=n_samples, p=cat_probs)

    X = np.zeros((n_samples, len(FEATURE_NAMES)), dtype=np.float64)

    for i, cat in enumerate(categories):
        cat_sec = 1.0 if cat == 0 else 0.0
        cat_fin = 1.0 if cat == 1 else 0.0
        cat_wrk = 1.0 if cat == 2 else 0.0
        cat_soc = 1.0 if cat == 3 else 0.0
        cat_prm = 1.0 if cat == 4 else 0.0

        if cat == 0:  # Security
            text_score = float(np.clip(rng.beta(4.8, 1.8), 0, 1))
            kw_urgency = float(np.clip(rng.beta(4.2, 2.0), 0, 1))
            sender_trust = float(rng.choice([1.0, 0.7, 0.2], p=[0.62, 0.26, 0.12]))
            source_rel = float(np.clip(rng.normal(0.86, 0.12), 0.15, 1.0))
            claimed = float(rng.choice([1.0, 0.75, 0.45], p=[0.55, 0.35, 0.10]))
            affinity = float(np.clip(rng.normal(0.75, 0.15), 0.1, 1.0))
        elif cat == 1:  # Finance
            text_score = float(np.clip(rng.beta(3.4, 2.5), 0, 1))
            kw_urgency = float(np.clip(rng.beta(3.0, 2.8), 0, 1))
            sender_trust = float(rng.choice([1.0, 0.7, 0.2], p=[0.50, 0.38, 0.12]))
            source_rel = float(np.clip(rng.normal(0.82, 0.14), 0.1, 1.0))
            claimed = float(rng.choice([1.0, 0.75, 0.45, 0.2], p=[0.25, 0.40, 0.25, 0.10]))
            affinity = float(np.clip(rng.normal(0.68, 0.18), 0.05, 1.0))
        elif cat == 2:  # Work
            text_score = float(np.clip(rng.beta(2.7, 2.9), 0, 1))
            kw_urgency = float(np.clip(rng.beta(2.4, 3.2), 0, 1))
            sender_trust = float(rng.choice([1.0, 0.7, 0.2], p=[0.42, 0.45, 0.13]))
            source_rel = float(rng.clip(rng.normal(0.76, 0.16), 0.1, 1.0))
            claimed = float(rng.choice([1.0, 0.75, 0.45, 0.2], p=[0.18, 0.32, 0.38, 0.12]))
            affinity = float(np.clip(rng.normal(0.64, 0.20), 0.05, 1.0))
        elif cat == 3:  # Social
            text_score = float(np.clip(rng.beta(1.9, 3.8), 0, 1))
            kw_urgency = float(np.clip(rng.beta(1.5, 4.4), 0, 1))
            sender_trust = float(rng.choice([1.0, 0.7, 0.2], p=[0.30, 0.45, 0.25]))
            source_rel = float(np.clip(rng.normal(0.58, 0.18), 0.05, 1.0))
            claimed = float(rng.choice([1.0, 0.75, 0.45, 0.2], p=[0.08, 0.20, 0.42, 0.30]))
            affinity = float(np.clip(rng.normal(0.55, 0.22), 0.05, 1.0))
        else:  # Promo (often tries to spoof claimed CRITICAL priority!)
            text_score = float(np.clip(rng.beta(1.6, 4.5), 0, 1))
            kw_urgency = float(np.clip(rng.beta(1.4, 4.8), 0, 1))
            sender_trust = float(rng.choice([1.0, 0.7, 0.2], p=[0.06, 0.24, 0.70]))
            source_rel = float(rng.clip(rng.normal(0.28, 0.16), 0.02, 0.85))
            claimed = float(rng.choice([1.0, 0.75, 0.45, 0.2], p=[0.42, 0.28, 0.15, 0.15]))
            affinity = float(np.clip(rng.normal(0.20, 0.15), 0.0, 0.75))

        age_factor = float(np.clip(rng.beta(1.4, 3.6), 0, 1))
        user_context = float(np.clip(rng.normal(0.62, 0.25), 0.0, 1.0))
        repetition = float(np.clip(rng.beta(1.3, 4.2), 0, 1))

        X[i] = [
            text_score,
            kw_urgency,
            sender_trust,
            source_rel,
            cat_sec,
            cat_fin,
            cat_wrk,
            cat_soc,
            cat_prm,
            age_factor,
            user_context,
            repetition,
            affinity,
            claimed,
        ]

    # True underlying generative log-odds + calibrated Gaussian noise
    true_weights = np.array(
        [
            2.15,   # textScore
            1.75,   # keywordUrgency
            1.20,   # senderTrust
            0.95,   # sourceReliability
            2.10,   # category_security
            1.25,   # category_finance
            0.55,   # category_work
            -0.75,  # category_social
            -2.10,  # category_promo
            0.95,   # ageFactor
            0.70,   # userContext
            0.55,   # repetition
            0.80,   # userAffinity
            0.22,   # senderClaimedPriority (kept intentionally weak)
        ],
        dtype=np.float64,
    )
    true_bias = -3.15
    logits = true_bias + X @ true_weights + rng.normal(0.0, 0.42, size=n_samples)
    probs = 1.0 / (1.0 + np.exp(-logits))
    y = (rng.uniform(0, 1, size=n_samples) < probs).astype(int)
    return X, y


def main():
    parser = argparse.ArgumentParser(description="Train AegisNotify logistic priority model")
    parser.add_argument("--samples", type=int, default=3000)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument(
        "--out",
        type=str,
        default="src/lib/priority/defaultWeights.json",
    )
    args = parser.parse_args()

    X, y = generate_synthetic_dataset(n_samples=args.samples, seed=args.seed)
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.20, random_state=args.seed, stratify=y
    )

    clf = LogisticRegression(
        C=1.0,
        penalty="l2",
        solver="lbfgs",
        max_iter=1000,
        random_state=args.seed,
    )

    cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=args.seed)
    cv_auc = cross_val_score(clf, X_train, y_train, cv=cv, scoring="roc_auc")
    cv_acc = cross_val_score(clf, X_train, y_train, cv=cv, scoring="accuracy")

    clf.fit(X_train, y_train)
    test_probs = clf.predict_proba(X_test)[:, 1]
    test_preds = (test_probs >= 0.5).astype(int)

    acc = float(accuracy_score(y_test, test_preds))
    prec = float(precision_score(y_test, test_preds, zero_division=0))
    rec = float(recall_score(y_test, test_preds, zero_division=0))
    f1 = float(f1_score(y_test, test_preds, zero_division=0))
    auc = float(roc_auc_score(y_test, test_probs))
    cm = confusion_matrix(y_test, test_preds).tolist()

    prob_true, prob_pred = calibration_curve(y_test, test_probs, n_bins=10, strategy="uniform")
    calibration_bins = []
    edges = np.linspace(0.0, 1.0, 11)
    for b in range(10):
        mask = (test_probs >= edges[b]) & (test_probs <= edges[b + 1] if b == 9 else test_probs < edges[b + 1])
        count = int(mask.sum())
        mean_pred = float(test_probs[mask].mean()) if count > 0 else round(float((edges[b] + edges[b + 1]) / 2), 3)
        mean_obs = float(y_test[mask].mean()) if count > 0 else 0.0
        calibration_bins.append({
            "binStart": round(float(edges[b]), 2),
            "binEnd": round(float(edges[b + 1]), 2),
            "predictedMean": round(mean_pred, 4),
            "observedFraction": round(mean_obs, 4),
            "count": count,
        })

    # Enforce senderClaimedPriority <= 0.35 & weight bounds [-4, 4]
    raw_weights = {
        name: round(float(np.clip(w, -4.0, 4.0)), 4)
        for name, w in zip(FEATURE_NAMES, clf.coef_[0])
    }
    raw_weights["senderClaimedPriority"] = min(raw_weights["senderClaimedPriority"], 0.35)

    payload = {
        "version": "1.0.0-logreg",
        "trainedAt": datetime.now(timezone.utc).isoformat(),
        "datasetSize": int(args.samples),
        "trainSize": int(len(X_train)),
        "testSize": int(len(X_test)),
        "bias": round(float(clf.intercept_[0]), 4),
        "weights": raw_weights,
        "thresholds": {
            "critical": 0.85,
            "high": 0.65,
            "normal": 0.35,
            "hysteresis": 0.04,
        },
        "hyperparams": {
            "learningRate": 0.05,
            "l2Regularization": 0.01,
            "gradientClip": 1.0,
            "weightMin": -4.0,
            "weightMax": 4.0,
            "coldStartFeedbackThreshold": 20,
            "ageTauSeconds": 120,
            "ageMaxBoost": 0.25,
            "ageMaxCeiling": 0.99,
            "decayHalfLifeSeconds": 3600,
            "securityFloorMinWeight": 1.5,
            "driftL2WarningThreshold": 1.8,
        },
        "metrics": {
            "cv5AucMean": round(float(cv_auc.mean()), 4),
            "cv5AucStd": round(float(cv_auc.std()), 4),
            "cv5AccuracyMean": round(float(cv_acc.mean()), 4),
            "testAccuracy": round(acc, 4),
            "testPrecision": round(prec, 4),
            "testRecall": round(rec, 4),
            "testF1": round(f1, 4),
            "testRocAuc": round(auc, 4),
            "confusionMatrix": cm,
            "calibrationBins": calibration_bins,
        },
        "modelCard": {
            "modelType": "Transparent L2-Regularized Logistic Regression (Online SGD Personalization)",
            "isDeepLearning": False,
            "intendedUse": "Continuous priority scoring p in [0,1] for encrypted notifications without storing raw text.",
            "trainingData": "3,000 synthetic privacy-safe feature vectors across security, finance, work, social, and promo categories.",
            "limitations": [
                "Not a neural network or deep language model; assumes linear log-odds additivity plus explicit safety rules.",
                "Subject to user feedback bias; mitigated with cold-start threshold (20 feedbacks), L2 decay, weight clamping [-4,4], and security floor lock.",
                "Privacy rule: only numeric textScore is scored/stored; raw plaintext never enters the model store.",
            ],
        },
    }

    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    print(f"Saved calibrated model weights and metrics to {out_path}")
    print(json.dumps(payload["metrics"], indent=2))


if __name__ == "__main__":
    main()
