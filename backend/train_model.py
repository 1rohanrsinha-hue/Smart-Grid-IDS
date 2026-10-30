"""
train_model.py
==============
Smart Grid IDS v2 - Random Forest Model Trainer
MIT Manipal - School of Computer Engineering
Cybersecurity Minor Project

Generates a synthetic dataset covering NORMAL operation plus all 12
attack signatures (using the exact same generator functions the live
simulator uses, via the `attacks` package), then trains a Random
Forest classifier and saves model.pkl + model_meta.json + dataset.csv.

HOW TO RUN:
    cd backend
    python train_model.py
"""

import os
import sys
import json
import pickle
import random

import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score, f1_score
from sklearn.preprocessing import LabelEncoder

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from attacks import ATTACKS, CLASSES, FEATURES, normal_readings, clip  # noqa: E402

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))

print("=" * 64)
print("  SMART GRID IDS v2 - MODEL TRAINER")
print("  MIT Manipal | Cybersecurity Minor Project")
print("=" * 64)

random.seed(42)
np.random.seed(42)

SAMPLES_PER_CLASS = 500  # 13 classes -> 6500 total samples

print(f"\n[1/4] Generating synthetic dataset "
      f"({len(CLASSES)} classes x {SAMPLES_PER_CLASS} samples)...")

rows = []

# NORMAL class: no attack generator, just baseline readings across a
# range of simulated ticks so the sinusoidal drift is well represented.
for i in range(SAMPLES_PER_CLASS):
    t = random.uniform(0, 1000)
    r = clip(normal_readings(t))
    r["label"] = "NORMAL"
    rows.append(r)

# Each attack: sample across the full intensity ramp (0 -> 1) so the
# model learns both "just starting" and "fully underway" signatures.
for attack_id, gen in ATTACKS.items():
    for i in range(SAMPLES_PER_CLASS):
        t = random.uniform(0, 1000)
        intensity = random.uniform(0.15, 1.0)  # skip near-zero (indistinguishable from NORMAL by design)
        r = gen.generate(t, intensity)
        r["label"] = attack_id
        rows.append(r)

df = pd.DataFrame(rows)[FEATURES + ["label"]].sample(frac=1, random_state=42).reset_index(drop=True)
df.to_csv(os.path.join(SCRIPT_DIR, "dataset.csv"), index=False)

print(f"    OK  Dataset generated: {len(df)} samples, {df['label'].nunique()} classes")
print(f"    Classes: {sorted(df['label'].unique())}")

# ─── FEATURE / LABEL SPLIT ──────────────────────────────────────────────────
print("\n[2/4] Preparing features...")

X = df[FEATURES].values
le = LabelEncoder()
le.fit(CLASSES)  # fix class order to match attacks.CLASSES
y = le.transform(df["label"])

X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42, stratify=y
)
print(f"    OK  Train: {len(X_train)} samples | Test: {len(X_test)} samples")

# ─── TRAIN RANDOM FOREST ────────────────────────────────────────────────────
print("\n[3/4] Training Random Forest classifier...")

model = RandomForestClassifier(
    n_estimators=200,
    max_depth=16,
    min_samples_split=4,
    random_state=42,
    n_jobs=-1,
    class_weight="balanced",
)
model.fit(X_train, y_train)
print("    OK  Training complete")

# ─── EVALUATE ──────────────────────────────────────────────────────────────
print("\n[4/4] Evaluating model...")

y_pred = model.predict(X_test)
acc = accuracy_score(y_test, y_pred)
f1 = f1_score(y_test, y_pred, average="weighted")

print(f"\n    Accuracy : {acc*100:.2f}%")
print(f"    F1 Score : {f1:.4f}")
print("\n    Classification Report:")
print(classification_report(y_test, y_pred, target_names=le.classes_, zero_division=0))

importances = model.feature_importances_
feat_imp = sorted(zip(FEATURES, importances), key=lambda x: -x[1])
print("    Top Features:")
for fname, fimp in feat_imp[:8]:
    print(f"      {fname:<28} {fimp:.4f}")

# ─── SAVE MODEL ─────────────────────────────────────────────────────────────
model_data = {
    "model": model,
    "label_encoder": le,
    "features": FEATURES,
    "accuracy": acc,
    "f1_score": f1,
    "classes": list(le.classes_),
}

with open(os.path.join(SCRIPT_DIR, "model.pkl"), "wb") as f:
    pickle.dump(model_data, f)

meta = {
    "accuracy": round(acc * 100, 2),
    "f1_score": round(f1, 4),
    "n_estimators": 200,
    "features": FEATURES,
    "classes": list(le.classes_),
    "train_samples": len(X_train),
    "test_samples": len(X_test),
}
with open(os.path.join(SCRIPT_DIR, "model_meta.json"), "w") as f:
    json.dump(meta, f, indent=2)

print(f"\n    OK  Model saved to backend/model.pkl")
print(f"    OK  Metadata saved to backend/model_meta.json")
print("\n" + "=" * 64)
print("  TRAINING COMPLETE. Run app.py next: python app.py")
print("=" * 64 + "\n")
