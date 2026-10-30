"""
train_models.py
=================
Smart Grid IDS v3 - Multi-Model Trainer

Generates the same synthetic 13-class dataset as train_model.py, then
trains THREE classifiers on it - Random Forest, SVM (RBF kernel,
probability=True), and a small MLP neural net - so the dashboard can
offer live model switching and a side-by-side accuracy/F1 comparison.

Saves:
    model_rf.pkl, model_svm.pkl, model_mlp.pkl   (one bundle each,
        same {model, label_encoder, features, accuracy, f1_score,
        classes} shape as the original model.pkl)
    model_comparison.json                          (metrics + confusion
        matrix per model, consumed by GET /api/models)
    dataset.csv                                     (shared dataset)

HOW TO RUN:
    cd backend
    python train_models.py
"""

import os
import sys
import json
import pickle
import random
import time

import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.svm import SVC
from sklearn.neural_network import MLPClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    classification_report, accuracy_score, f1_score, confusion_matrix,
)
from sklearn.preprocessing import LabelEncoder, StandardScaler

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from attacks import ATTACKS, CLASSES, FEATURES, normal_readings, clip  # noqa: E402

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))

print("=" * 64)
print("  SMART GRID IDS v3 - MULTI-MODEL TRAINER (RF + SVM + MLP)")
print("  MIT Manipal | Cybersecurity Minor Project")
print("=" * 64)

random.seed(42)
np.random.seed(42)

SAMPLES_PER_CLASS = 500

print(f"\n[1/5] Generating synthetic dataset "
      f"({len(CLASSES)} classes x {SAMPLES_PER_CLASS} samples)...")

rows = []
for i in range(SAMPLES_PER_CLASS):
    t = random.uniform(0, 1000)
    r = clip(normal_readings(t))
    r["label"] = "NORMAL"
    rows.append(r)

for attack_id, gen in ATTACKS.items():
    for i in range(SAMPLES_PER_CLASS):
        t = random.uniform(0, 1000)
        intensity = random.uniform(0.15, 1.0)
        r = gen.generate(t, intensity)
        r["label"] = attack_id
        rows.append(r)

df = pd.DataFrame(rows)[FEATURES + ["label"]].sample(frac=1, random_state=42).reset_index(drop=True)
df.to_csv(os.path.join(SCRIPT_DIR, "dataset.csv"), index=False)
print(f"    OK  Dataset generated: {len(df)} samples, {df['label'].nunique()} classes")

print("\n[2/5] Preparing features...")
X = df[FEATURES].values
le = LabelEncoder()
le.fit(CLASSES)
y = le.transform(df["label"])

X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42, stratify=y
)
print(f"    OK  Train: {len(X_train)} samples | Test: {len(X_test)} samples")

# SVM and MLP are sensitive to feature scale; RF is not, but scaling
# doesn't hurt it and lets us keep one shared preprocessing story if
# needed later. We store the scaler INSIDE each non-RF model bundle
# so app.py doesn't need to know which models need it.
scaler = StandardScaler().fit(X_train)
X_train_scaled = scaler.transform(X_train)
X_test_scaled = scaler.transform(X_test)

results = {}


def evaluate_and_save(name, filename, model, X_tr, y_tr, X_te, y_te, extra_bundle=None):
    print(f"\n[.../5] Training {name}...")
    start = time.time()
    model.fit(X_tr, y_tr)
    elapsed = time.time() - start
    y_pred = model.predict(X_te)
    acc = accuracy_score(y_te, y_pred)
    f1 = f1_score(y_te, y_pred, average="weighted")
    cm = confusion_matrix(y_te, y_pred, labels=range(len(le.classes_))).tolist()
    print(f"    OK  {name}: accuracy={acc*100:.2f}%  f1={f1:.4f}  train_time={elapsed:.2f}s")

    bundle = {
        "model": model,
        "label_encoder": le,
        "features": FEATURES,
        "accuracy": acc,
        "f1_score": f1,
        "classes": list(le.classes_),
    }
    if extra_bundle:
        bundle.update(extra_bundle)

    with open(os.path.join(SCRIPT_DIR, filename), "wb") as f:
        pickle.dump(bundle, f)

    results[name] = {
        "accuracy": round(acc * 100, 2),
        "f1_score": round(f1, 4),
        "train_time_sec": round(elapsed, 2),
        "confusion_matrix": cm,
        "file": filename,
    }


print("\n[3/5] Random Forest")
rf = RandomForestClassifier(
    n_estimators=200, max_depth=16, min_samples_split=4,
    random_state=42, n_jobs=-1, class_weight="balanced",
)
evaluate_and_save("RF", "model_rf.pkl", rf, X_train, y_train, X_test, y_test)

print("\n[4/5] SVM (RBF kernel)")
svm = SVC(kernel="rbf", C=10, gamma="scale", probability=True, random_state=42,
          class_weight="balanced")
evaluate_and_save("SVM", "model_svm.pkl", svm, X_train_scaled, y_train, X_test_scaled, y_test,
                   extra_bundle={"scaler": scaler})

print("\n[5/5] Neural Net (MLP)")
mlp = MLPClassifier(
    hidden_layer_sizes=(64, 32), activation="relu", max_iter=400,
    random_state=42, early_stopping=True,
)
evaluate_and_save("MLP", "model_mlp.pkl", mlp, X_train_scaled, y_train, X_test_scaled, y_test,
                   extra_bundle={"scaler": scaler})

meta = {
    "classes": list(le.classes_),
    "features": FEATURES,
    "train_samples": len(X_train),
    "test_samples": len(X_test),
    "models": results,
}
with open(os.path.join(SCRIPT_DIR, "model_comparison.json"), "w") as f:
    json.dump(meta, f, indent=2)

# Keep model_meta.json / model.pkl (legacy single-model files) pointing at RF
# for any older code path that still reads them.
with open(os.path.join(SCRIPT_DIR, "model_rf.pkl"), "rb") as f:
    rf_bundle = pickle.load(f)
with open(os.path.join(SCRIPT_DIR, "model.pkl"), "wb") as f:
    pickle.dump(rf_bundle, f)
with open(os.path.join(SCRIPT_DIR, "model_meta.json"), "w") as f:
    json.dump({
        "accuracy": results["RF"]["accuracy"],
        "f1_score": results["RF"]["f1_score"],
        "n_estimators": 200,
        "features": FEATURES,
        "classes": list(le.classes_),
        "train_samples": len(X_train),
        "test_samples": len(X_test),
    }, f, indent=2)

print("\n" + "=" * 64)
print("  ALL MODELS TRAINED")
for name, r in results.items():
    print(f"    {name:<5} accuracy={r['accuracy']}%  f1={r['f1_score']}")
print("  Saved: model_rf.pkl, model_svm.pkl, model_mlp.pkl, model_comparison.json")
print("  TRAINING COMPLETE. Run app.py next: python app.py")
print("=" * 64 + "\n")
