"""
eval_public_dataset.py
======================
Offline evaluation of our four model types on a PUBLIC dataset
(WUSTL-IIoT-2021), so the report has honest numbers instead of the ~100%
we get on our own synthetic generators.

This script is EVALUATION ONLY. It does not touch the dashboard, the
22-feature pipeline or the pickled demo models. It trains separate models
on the public dataset's own features and writes:

    backend/real_dataset_eval.json     all numbers (see keys at the bottom)
    docs/eval_plots/cm_<model>.png     confusion matrices (raw + row-normalised)

Run:   cd backend && python3 eval_public_dataset.py
Needs: data/wustl_iiot_2021.csv  (see README for the download link)

What it does
------------
1. Load + inspect the CSV (class counts, NaN, inf, duplicates, constants).
2. Clean it (drop identifier/leakage columns, duplicate columns, duplicate
   rows, absurd outliers).
3. Stratified 80/20 split (seed 42) + 5-fold stratified cross-validation.
   Scalers are fitted on the training part only (inside a Pipeline).
4. Train RandomForest, SVC, MLP and a single DecisionTree baseline, using
   the same hyper-parameters as backend/train_models.py.
5. Report per-class precision/recall/F1 (with test support), macro-F1,
   weighted-F1 and the false-positive rate on normal traffic. Plain
   accuracy is stored but is NOT the headline: ~95% of rows are normal,
   so a model that always says "normal" would already score ~95%.
6. Robustness: Gaussian noise on the test features.
7. Seed stability: the hold-out split + training repeated for 5 more seeds.
8. EXTRA (separate from the main results): time-ordered split by StartTime
   (train on the first 80%, test on the last 20%). StartTime is used only to
   order rows here; it is never a model feature.

The SVM is trained on at most 100,000 rows: every attack row of the training
split plus a random subsample of normal rows. It is always evaluated on the
full test set.

Multi-class label = `Traffic` (normal, DoS, Reconn, CommInj, Backdoor).
Binary view = `Target` (0 normal / 1 attack); we check it agrees with
`Traffic`, and derive binary metrics from the multi-class predictions
(predicted anything-but-normal => "attack").
"""
import json
import os
import sys
import time
import warnings

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (accuracy_score, confusion_matrix, f1_score,
                             precision_recall_fscore_support)
from sklearn.model_selection import StratifiedKFold, train_test_split
from sklearn.neural_network import MLPClassifier
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.svm import SVC
from sklearn.tree import DecisionTreeClassifier

warnings.filterwarnings("ignore")

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(SCRIPT_DIR)
CSV_PATH = os.path.join(ROOT, "data", "wustl_iiot_2021.csv")
OUT_JSON = os.path.join(SCRIPT_DIR, "real_dataset_eval.json")
PLOT_DIR = os.path.join(ROOT, "docs", "eval_plots")

DATASET_NAME = "WUSTL-IIoT-2021"
SOURCE_URL = "https://classes.engineering.wustl.edu/~jain/iiot2/index.html"

SEED = 42
TEST_SIZE = 0.2
N_FOLDS = 5
SVM_MAX_TRAIN = 100_000     # SVC is O(n^2..n^3): train on a subsample (all attack rows kept)
MIN_RELIABLE_SUPPORT = 30   # classes with fewer test rows are flagged unreliable
SEEDS = [1, 2, 3, 4, 5]    # extra seeds for the seed-stability check
TEMPORAL_TRAIN_FRACTION = 0.8
NOISE_LEVELS = [0.25, 0.5, 1.0]   # multiples of each feature's std
MAX_SANE_DUR = 3600.0       # seconds; see cleaning step

CLASSES = ["normal", "DoS", "Reconn", "CommInj", "Backdoor"]
LABEL_COL, BINARY_COL = "Traffic", "Target"

# Columns removed before modelling, and why.
DROP_COLUMNS = {
    "StartTime": "timestamp: attacks were run in separate time windows, so time alone reveals the label",
    "LastTime": "timestamp: same reason as StartTime",
    "SrcAddr": "source IP: each attack came from fixed hosts, so the IP identifies the attack (dataset page says drop)",
    "DstAddr": "destination IP: same reason as SrcAddr (dataset page says drop)",
    "sIpId": "source IP-ID counter: unique to the attack tools (dataset page says drop)",
    "dIpId": "destination IP-ID counter: same reason as sIpId (dataset page says drop)",
    "Sport": "source port: ephemeral port, essentially a per-flow identifier / lets the model memorise flows",
    "Dport": "destination port: tied to the service targeted in the testbed, so it shortcuts the label",
}


def banner(text):
    print("\n" + "=" * 70 + f"\n  {text}\n" + "=" * 70)


# --------------------------------------------------------------------------
# 1. Load + inspect
# --------------------------------------------------------------------------
def load_and_inspect():
    if not os.path.exists(CSV_PATH):
        sys.exit(f"Dataset not found at {CSV_PATH}\n"
                 f"Download wustl_iiot_2021.zip from {SOURCE_URL} and unzip it into data/.")
    banner("1. DATA INSPECTION")
    df = pd.read_csv(CSV_PATH)
    num = df.select_dtypes(include="number")
    info = {
        "rows": int(len(df)),
        "columns": int(df.shape[1]),
        "class_counts": {k: int(v) for k, v in df[LABEL_COL].value_counts().items()},
        "missing_values": int(df.isna().sum().sum()),
        "inf_values": int(np.isinf(num).sum().sum()),
        "exact_duplicate_rows": int(df.duplicated().sum()),
        "constant_columns": [c for c in df.columns if df[c].nunique() <= 1],
        "traffic_vs_target_consistent": bool(
            (df[BINARY_COL] == (df[LABEL_COL] != "normal").astype(int)).all()),
    }
    print(f"  shape: {df.shape}")
    print("  class counts (Traffic):")
    for k, v in info["class_counts"].items():
        print(f"      {k:<10}{v:>10,}  ({100*v/len(df):.3f}%)")
    print(f"  missing: {info['missing_values']}   inf: {info['inf_values']}   "
          f"exact duplicate rows: {info['exact_duplicate_rows']}")
    print(f"  constant columns: {info['constant_columns'] or 'none'}")
    print(f"  Traffic and Target consistent: {info['traffic_vs_target_consistent']}")
    return df, info


# --------------------------------------------------------------------------
# 2. Clean
# --------------------------------------------------------------------------
def clean(df):
    banner("2. CLEANING")
    log = {"rows_before": int(len(df))}
    df = df.copy()

    # Binary flag must agree with the category label, otherwise one is wrong.
    assert (df[BINARY_COL] == (df[LABEL_COL] != "normal").astype(int)).all()

    df = df.drop(columns=list(DROP_COLUMNS))
    print(f"  dropped {len(DROP_COLUMNS)} identifier/leakage columns")

    # Target is just a 0/1 copy of Traffic, so it must not be a feature.
    y_bin = df.pop(BINARY_COL)
    y = df.pop(LABEL_COL)
    X = df

    # NaN / inf: none in this dataset, but handled so the script is safe on
    # other versions of the file. Rows with them are dropped (not imputed).
    X = X.replace([np.inf, -np.inf], np.nan)
    bad = X.isna().any(axis=1)
    log["rows_dropped_nan_inf"] = int(bad.sum())

    # Identical columns carry no extra information (Sum, Min, Max, RunTime
    # are exact copies of each other here). Keep the first, drop the rest.
    dup_cols = []
    cols = list(X.columns)
    for i, a in enumerate(cols):
        if a in dup_cols:
            continue
        for b in cols[i + 1:]:
            if b not in dup_cols and np.array_equal(X[a].values, X[b].values):
                dup_cols.append(b)
    X = X.drop(columns=dup_cols)
    log["duplicate_columns_dropped"] = dup_cols
    print(f"  dropped exact-duplicate columns {dup_cols}")

    # Absurd durations: two normal flows last 3-5 days, the rest are <= 60 s.
    # They would dominate the feature std (and so the noise test), so drop.
    extreme = X["Dur"] > MAX_SANE_DUR
    log["rows_dropped_extreme_dur"] = int(extreme.sum())
    bad = bad | extreme
    X, y, y_bin = X[~bad], y[~bad], y_bin[~bad]

    # Duplicate rows (on features + label) are removed BEFORE splitting, so
    # an identical row can never sit in both train and test. After dropping
    # the timestamp/IP columns many flows become identical.
    full = X.assign(_y=y.values)
    dup = full.duplicated().values
    log["duplicate_rows_removed"] = int(dup.sum())
    log["removed_per_class"] = {k: int(v) for k, v in y[dup].value_counts().items()}
    X, y, y_bin = X[~dup], y[~dup], y_bin[~dup]
    # Same features but different labels would be contradictory; check.
    log["conflicting_label_rows"] = int(X.duplicated(keep=False).sum())

    log["rows_after"] = int(len(X))
    log["class_counts_after"] = {k: int(v) for k, v in y.value_counts().items()}
    log["feature_columns"] = list(X.columns)
    print(f"  dropped NaN/inf rows: {log['rows_dropped_nan_inf']}, "
          f"extreme-Dur rows: {log['rows_dropped_extreme_dur']}")
    print(f"  duplicate rows removed: {log['duplicate_rows_removed']:,} "
          f"{log['removed_per_class']}")
    print(f"  contradictory duplicates (same features, different label): "
          f"{log['conflicting_label_rows']}")
    print(f"  rows: {log['rows_before']:,} -> {log['rows_after']:,}; "
          f"{X.shape[1]} features")
    print(f"  classes after: {log['class_counts_after']}")
    return X, y, y_bin, log


# --------------------------------------------------------------------------
# 3. Models (settings match backend/train_models.py)
# --------------------------------------------------------------------------
def make_models(seed=SEED):
    return {
        # Trees do not need scaling.
        "RF": RandomForestClassifier(
            n_estimators=200, max_depth=16, min_samples_split=4,
            random_state=seed, n_jobs=-1, class_weight="balanced"),
        # SVM / MLP need scaling; the scaler is inside the pipeline, so it is
        # always fitted on the training data only.
        "SVM": make_pipeline(StandardScaler(), SVC(
            kernel="rbf", C=10, gamma="scale", random_state=seed,
            class_weight="balanced")),
        "MLP": make_pipeline(StandardScaler(), MLPClassifier(
            hidden_layer_sizes=(64, 32), activation="relu", max_iter=400,
            random_state=seed, early_stopping=True)),
        # Single tree baseline: shows how much of the task is "easy".
        "DT": DecisionTreeClassifier(random_state=seed, class_weight="balanced"),
    }


def train_subsample(name, X, y, seed=SEED):
    """The SVM trains on at most SVM_MAX_TRAIN rows: ALL attack rows are kept
    and only the (huge) normal class is randomly subsampled to fill the rest.
    Other models use the full training set."""
    if name != "SVM" or len(X) <= SVM_MAX_TRAIN:
        return X, y
    is_attack = (y.values != 0)                    # integer label 0 == normal
    att_idx = np.flatnonzero(is_attack)
    norm_idx = np.flatnonzero(~is_attack)
    n_norm = max(0, SVM_MAX_TRAIN - len(att_idx))
    keep_norm = np.random.default_rng(seed).choice(
        norm_idx, size=min(n_norm, len(norm_idx)), replace=False)
    idx = np.sort(np.concatenate([att_idx, keep_norm]))
    return X.iloc[idx], y.iloc[idx]


# --------------------------------------------------------------------------
# 4. Metrics
# --------------------------------------------------------------------------
def decode(v):
    """Models are trained on integer labels (MLP early stopping needs numeric
    labels in this scikit-learn version); turn them back into class names."""
    return np.array(CLASSES)[np.asarray(v)]


def metrics(y_true, y_pred):
    """All metrics for one model/test set. FPR = normal rows predicted as attack."""
    y_true, y_pred = decode(y_true), decode(y_pred)
    p, r, f, s = precision_recall_fscore_support(
        y_true, y_pred, labels=CLASSES, zero_division=0)
    cm = confusion_matrix(y_true, y_pred, labels=CLASSES)
    n_normal = cm[0].sum()
    fpr = float((n_normal - cm[0, 0]) / n_normal) if n_normal else float("nan")

    # Binary view derived from the multi-class prediction.
    t_att = (np.asarray(y_true) != "normal")
    p_att = (np.asarray(y_pred) != "normal")
    tp, fp = int((t_att & p_att).sum()), int((~t_att & p_att).sum())
    fn = int((t_att & ~p_att).sum())
    b_prec = tp / (tp + fp) if tp + fp else 0.0
    b_rec = tp / (tp + fn) if tp + fn else 0.0
    b_f1 = 2 * b_prec * b_rec / (b_prec + b_rec) if b_prec + b_rec else 0.0

    return {
        "macro_f1": float(f1_score(y_true, y_pred, labels=CLASSES, average="macro", zero_division=0)),
        "weighted_f1": float(f1_score(y_true, y_pred, labels=CLASSES, average="weighted", zero_division=0)),
        "accuracy_not_headline": float(accuracy_score(y_true, y_pred)),
        "false_positive_rate_on_normal": fpr,
        "binary": {"precision": b_prec, "recall": b_rec, "f1": b_f1,
                   "false_positive_rate": fpr, "false_negatives": fn,
                   "false_positives": fp},
        "per_class": {
            c: {"precision": float(p[i]), "recall": float(r[i]), "f1": float(f[i]),
                "test_support": int(s[i]),
                "reliable": bool(s[i] >= MIN_RELIABLE_SUPPORT)}
            for i, c in enumerate(CLASSES)},
        "confusion_matrix": cm.tolist(),
        "confusion_matrix_labels": CLASSES,
    }


def plot_cm(name, cm):
    cm = np.array(cm)
    norm = cm / cm.sum(axis=1, keepdims=True).clip(min=1)
    fig, axes = plt.subplots(1, 2, figsize=(12, 5))
    for ax, data, title, fmt in ((axes[0], cm, "counts", "d"),
                                 (axes[1], norm, "row-normalised (recall)", ".2f")):
        im = ax.imshow(data, cmap="Blues")
        ax.set_xticks(range(len(CLASSES)), CLASSES, rotation=30)
        ax.set_yticks(range(len(CLASSES)), CLASSES)
        ax.set_xlabel("Predicted")
        ax.set_ylabel("True")
        ax.set_title(f"{name} - {title}")
        for i in range(len(CLASSES)):
            for j in range(len(CLASSES)):
                v = data[i, j]
                ax.text(j, i, format(v, fmt), ha="center", va="center",
                        color="white" if v > data.max() / 2 else "black", fontsize=8)
        fig.colorbar(im, ax=ax, fraction=0.046)
    fig.suptitle(f"{DATASET_NAME} test set - {name}")
    fig.tight_layout()
    os.makedirs(PLOT_DIR, exist_ok=True)
    fig.savefig(os.path.join(PLOT_DIR, f"cm_{name.lower()}.png"), dpi=130)
    plt.close(fig)


# --------------------------------------------------------------------------
# 5. Main
# --------------------------------------------------------------------------
def main():
    t_start = time.time()
    raw, inspect_info = load_and_inspect()
    start_time = pd.to_datetime(raw["StartTime"])   # kept ONLY for the time-ordered check
    X, y, y_bin, clean_log = clean(raw)
    del raw
    y_names = y                                   # keep names for reporting
    y = y.map({c: i for i, c in enumerate(CLASSES)})   # integer labels for the models

    banner("3. SPLIT")
    X_tr, X_te, y_tr, y_te = train_test_split(
        X, y, test_size=TEST_SIZE, stratify=y, random_state=SEED)
    split = {"train_rows": int(len(X_tr)), "test_rows": int(len(X_te)),
             "test_size": TEST_SIZE, "seed": SEED,
             "train_class_counts": {CLASSES[k]: int(v) for k, v in y_tr.value_counts().items()},
             "test_class_counts": {CLASSES[k]: int(v) for k, v in y_te.value_counts().items()}}
    print(f"  train {len(X_tr):,}  test {len(X_te):,}  (stratified, seed {SEED})")
    print(f"  test class counts: {split['test_class_counts']}")
    small = [c for c, n in split["test_class_counts"].items() if n < MIN_RELIABLE_SUPPORT]
    print(f"  classes with < {MIN_RELIABLE_SUPPORT} test rows (unreliable): {small or 'none'}")
    print(f"  SVM trains on <= {SVM_MAX_TRAIN:,} rows: ALL attack rows of the training split "
          f"+ a random subsample of normal rows (evaluated on the FULL test set); "
          f"RF/MLP/DT use all {len(X_tr):,}.")

    # ---- hold-out evaluation + noise robustness ----
    banner("4. TRAIN + HOLD-OUT EVALUATION")
    # Noise scale 1 (as specified): each feature's plain std on the training set.
    # Network features are heavy-tailed (e.g. Load std ~5e7 while a typical
    # flow is ~1e5), so this noise swamps the typical values of those features.
    # Noise scale 2 (supplementary): std of the feature after clipping it to
    # its 1st-99th percentile, i.e. noise sized to the bulk of the data.
    feat_std = X_tr.std().values
    lo, hi = X_tr.quantile(0.01), X_tr.quantile(0.99)
    feat_std_robust = X_tr.clip(lo, hi, axis=1).std().values
    rng = np.random.default_rng(SEED)
    unit = rng.normal(0.0, 1.0, X_te.shape)        # same draw reused for every level/model
    noise = {lvl: unit * feat_std * lvl for lvl in NOISE_LEVELS}
    noise_robust = {lvl: unit * feat_std_robust * lvl for lvl in NOISE_LEVELS}

    results = {}
    for name, model in make_models().items():
        Xs, ys = train_subsample(name, X_tr, y_tr)
        t0 = time.time()
        model.fit(Xs, ys)
        fit_s = time.time() - t0
        t0 = time.time()
        m = metrics(y_te, model.predict(X_te))
        m["train_rows_used"] = int(len(Xs))
        m["fit_seconds"] = round(fit_s, 1)
        m["predict_seconds"] = round(time.time() - t0, 1)
        print(f"  {name:<4} fit {fit_s:7.1f}s  macro-F1={m['macro_f1']:.4f}  "
              f"weighted-F1={m['weighted_f1']:.4f}  FPR(normal)={m['false_positive_rate_on_normal']:.4f}")
        plot_cm(name, m["confusion_matrix"])

        # Noise is added to the RAW features; the pipeline then scales them
        # with the training-set scaler (never refitted on noisy data).
        for key, nz in (("noise_robustness_macro_f1", noise),
                        ("noise_robustness_macro_f1_clipped_std", noise_robust)):
            m[key] = {"0.0": m["macro_f1"]}
            for lvl in NOISE_LEVELS:
                pred = model.predict(pd.DataFrame(X_te.values + nz[lvl], columns=X_te.columns))
                m[key][str(lvl)] = float(f1_score(
                    decode(y_te), decode(pred), labels=CLASSES, average="macro", zero_division=0))
            print(f"       {key}: { {k: round(v, 4) for k, v in m[key].items()} }")
        results[name] = m

    # ---- 5-fold stratified cross-validation ----
    banner(f"5. {N_FOLDS}-FOLD STRATIFIED CROSS-VALIDATION (whole cleaned dataset)")
    skf = StratifiedKFold(n_splits=N_FOLDS, shuffle=True, random_state=SEED)
    folds = list(skf.split(X, y))
    for name in results:
        mf, wf, fp = [], [], []
        t0 = time.time()
        for tr, te in folds:
            model = make_models()[name]
            Xs, ys = train_subsample(name, X.iloc[tr], y.iloc[tr])
            model.fit(Xs, ys)
            m = metrics(y.iloc[te], model.predict(X.iloc[te]))
            mf.append(m["macro_f1"]); wf.append(m["weighted_f1"])
            fp.append(m["false_positive_rate_on_normal"])
        results[name]["cross_validation"] = {
            "folds": N_FOLDS,
            "macro_f1_mean": float(np.mean(mf)), "macro_f1_std": float(np.std(mf)),
            "macro_f1_per_fold": [float(v) for v in mf],
            "weighted_f1_mean": float(np.mean(wf)),
            "fpr_normal_mean": float(np.mean(fp)),
        }
        print(f"  {name:<4} macro-F1 {np.mean(mf):.4f} +/- {np.std(mf):.4f}   "
              f"weighted-F1 {np.mean(wf):.4f}   FPR(normal) {np.mean(fp):.4f}   "
              f"({time.time()-t0:.0f}s)")

    # ---- seed stability ----
    banner(f"5b. SEED STABILITY (stratified hold-out split + training, seeds {SEEDS})")
    seed_runs = {n: {"macro_f1": [], "f1_CommInj": [], "f1_Backdoor": [], "f1_Reconn": []}
                 for n in results}
    for seed in SEEDS:
        a, b, ya, yb = train_test_split(X, y, test_size=TEST_SIZE, stratify=y, random_state=seed)
        for name in results:
            model = make_models(seed)[name]
            Xs, ys = train_subsample(name, a, ya, seed)
            model.fit(Xs, ys)
            m = metrics(yb, model.predict(b))
            seed_runs[name]["macro_f1"].append(m["macro_f1"])
            for c in ("CommInj", "Backdoor", "Reconn"):
                seed_runs[name][f"f1_{c}"].append(m["per_class"][c]["f1"])
        print(f"  seed {seed} done")
    seed_stability = {}
    for name, d in seed_runs.items():
        seed_stability[name] = {"seeds": SEEDS, **{
            k: {"values": [float(x) for x in v], "mean": float(np.mean(v)), "std": float(np.std(v))}
            for k, v in d.items()}}
        r = seed_stability[name]
        print(f"  {name:<4} macro-F1 {r['macro_f1']['mean']:.4f} +/- {r['macro_f1']['std']:.4f}   "
              f"CommInj F1 {r['f1_CommInj']['mean']:.4f} +/- {r['f1_CommInj']['std']:.4f}   "
              f"Backdoor F1 {r['f1_Backdoor']['mean']:.4f} +/- {r['f1_Backdoor']['std']:.4f}")

    # ---- EXTRA: time-ordered check ----
    banner("5c. EXTRA - TIME-ORDERED CHECK (train on first 80% by StartTime, test on last 20%)")
    order = start_time.loc[X.index].sort_values(kind="stable").index
    n_tr = int(TEMPORAL_TRAIN_FRACTION * len(order))
    tr_idx, te_idx = order[:n_tr], order[n_tr:]
    Xt_tr, Xt_te, yt_tr, yt_te = X.loc[tr_idx], X.loc[te_idx], y.loc[tr_idx], y.loc[te_idx]
    temporal = {
        "train_rows": int(len(tr_idx)), "test_rows": int(len(te_idx)),
        "train_period": [str(start_time.loc[tr_idx].min()), str(start_time.loc[tr_idx].max())],
        "test_period": [str(start_time.loc[te_idx].min()), str(start_time.loc[te_idx].max())],
        "train_class_counts": {c: int((yt_tr == i).sum()) for i, c in enumerate(CLASSES)},
        "test_class_counts": {c: int((yt_te == i).sum()) for i, c in enumerate(CLASSES)},
        "class_time_ranges": {c: [str(start_time.loc[y.index[y == i]].min()),
                                 str(start_time.loc[y.index[y == i]].max())]
                              for i, c in enumerate(CLASSES)},
        "note": ("Duplicates were removed globally before this split. Macro-F1 averages only the "
                 "classes that have rows in the test period; classes without test rows get null."),
        "models": {},
    }
    print(f"  train {len(tr_idx):,} rows {temporal['train_period']}")
    print(f"  test  {len(te_idx):,} rows {temporal['test_period']}")
    print(f"  time range of each class: {temporal['class_time_ranges']}")
    print(f"  train class counts: {temporal['train_class_counts']}")
    print(f"  test  class counts: {temporal['test_class_counts']}")
    present = [i for i, c in enumerate(CLASSES) if temporal["test_class_counts"][c] > 0]
    for name in ("RF", "DT"):
        model = make_models()[name]
        model.fit(Xt_tr, yt_tr)
        pred = model.predict(Xt_te)
        p, r, f, sup = precision_recall_fscore_support(
            yt_te, pred, labels=list(range(len(CLASSES))), zero_division=0)
        per_class = {}
        for i, c in enumerate(CLASSES):
            if sup[i] == 0:
                per_class[c] = {"test_support": 0, "f1": None, "precision": None, "recall": None,
                                "reliable": False, "note": "no rows of this class in the test period"}
            else:
                per_class[c] = {"test_support": int(sup[i]), "f1": float(f[i]),
                                "precision": float(p[i]), "recall": float(r[i]),
                                "reliable": bool(sup[i] >= MIN_RELIABLE_SUPPORT)}
        macro = float(f1_score(yt_te, pred, labels=present, average="macro", zero_division=0))
        temporal["models"][name] = {"macro_f1_over_classes_present": macro,
                                    "classes_in_macro": [CLASSES[i] for i in present],
                                    "per_class": per_class}
        print(f"  {name}: macro-F1 (classes present: {[CLASSES[i] for i in present]}) = {macro:.4f}")
        for c in CLASSES:
            pc = per_class[c]
            if pc["f1"] is None:
                print(f"      {c:<9}no test rows in this period - not evaluated")
            else:
                flag = "" if pc["reliable"] else "   <-- UNRELIABLE (<30 test rows)"
                print(f"      {c:<9}F1 {pc['f1']:.4f}  (P {pc['precision']:.4f} R {pc['recall']:.4f}) "
                      f"n={pc['test_support']}{flag}")

    # ---- mapping to our attack types ----
    mapping = {
        "DoS": {"our_attack": "DDOS", "note": "volumetric flooding"},
        "Reconn": {"our_attack": "PORT_SCAN", "note": "reconnaissance / scanning"},
        "CommInj": {"our_attack": "CMD_INJECT", "note": "command injection"},
        "Backdoor": {"our_attack": "MALWARE", "note": "approximate: backdoor ~ malware"},
    }

    out = {
        "dataset": DATASET_NAME, "source_url": SOURCE_URL,
        "licence": "No licence stated on the source page; used for research and evaluation.",
        "inspection_raw": inspect_info,
        "cleaning": {**clean_log, "columns_dropped_identifier_or_leakage": DROP_COLUMNS},
        "split": split,
        "svm_training_set": (f"all attack rows of the training split + random subsample of normal rows, "
                             f"at most {SVM_MAX_TRAIN} rows in total"),
        "noise_levels_in_feature_std": NOISE_LEVELS,
        "noise_note": ("noise_robustness_macro_f1 uses each feature's plain std (as specified); "
                       "..._clipped_std uses the std after clipping to the 1st-99th percentile "
                       "(supplementary, because plain std is dominated by heavy tails)."),
        "classes": CLASSES,
        "class_mapping_to_our_attacks": mapping,
        "models": results,
        "seed_stability": seed_stability,
        "extra_time_ordered_check": temporal,
        "note": ("Separate models trained on a public dataset. NOT the dashboard "
                 "models, which are trained on synthetic data."),
        "runtime_seconds": round(time.time() - t_start),
    }
    with open(OUT_JSON, "w") as f:
        json.dump(out, f, indent=2)

    # ---- summary ----
    banner("SUMMARY (hold-out test set)")
    print(f"{'Model':<6}{'macro-F1':>9}{'wtd-F1':>9}{'FPR norm':>10}{'CV macro-F1':>16}"
          f"{'noise .25':>10}{'.5':>8}{'1.0':>8}  | clipped-std noise .25/.5/1.0")
    for n, m in results.items():
        nz = m["noise_robustness_macro_f1"]
        cv = m["cross_validation"]
        print(f"{n:<6}{m['macro_f1']:>9.4f}{m['weighted_f1']:>9.4f}"
              f"{m['false_positive_rate_on_normal']:>10.4f}"
              f"{cv['macro_f1_mean']:>10.4f}+/-{cv['macro_f1_std']:.3f}"
              f"{nz['0.25']:>10.4f}{nz['0.5']:>8.4f}{nz['1.0']:>8.4f}"
              + "  | " + " / ".join(f"{m['noise_robustness_macro_f1_clipped_std'][k]:.4f}"
                                    for k in ("0.25", "0.5", "1.0")))
    print("\nPer-class (precision / recall / F1 / test rows):")
    for n, m in results.items():
        print(f"  {n}")
        for c in CLASSES:
            pc = m["per_class"][c]
            flag = "" if pc["reliable"] else "   <-- UNRELIABLE (<30 test rows)"
            print(f"    {c:<9}{pc['precision']:.4f}  {pc['recall']:.4f}  {pc['f1']:.4f}  "
                  f"n={pc['test_support']}{flag}")
    print(f"\nSaved {OUT_JSON}\nPlots in {PLOT_DIR}\nTotal time {time.time()-t_start:.0f}s")


if __name__ == "__main__":
    main()
