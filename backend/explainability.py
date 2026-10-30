"""
explainability.py
===================
"Why was this flagged?" - top contributing features for the active
model's current prediction.

Method (fast, dependency-light, explainable in a viva):
  contribution[feature] = model.feature_importances_[feature]
                            * |live_value - NORMAL_mean[feature]| / NORMAL_std[feature]

This rewards features that are BOTH generally important to the model
AND unusually far from baseline right now - which is what a human
analyst would look at first. For models without feature_importances_
(SVM, MLP) we fall back to a pure deviation (z-score) ranking, which
is model-agnostic.

If `shap` is importable, we prefer a real SHAP TreeExplainer for the
Random Forest specifically (it supports tree models natively and
cheaply); everything else always uses the deviation-weighted fallback.
"""

import os
import numpy as np
import pandas as pd

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
DATASET_PATH = os.path.join(SCRIPT_DIR, "dataset.csv")

try:
    import shap  # noqa: F401
    _HAS_SHAP = True
except ImportError:
    _HAS_SHAP = False

_normal_stats_cache = None


def _normal_stats(features):
    """Mean/std of every feature under the NORMAL class, cached."""
    global _normal_stats_cache
    if _normal_stats_cache is not None:
        return _normal_stats_cache
    if not os.path.exists(DATASET_PATH):
        _normal_stats_cache = ({f: 0.0 for f in features}, {f: 1.0 for f in features})
        return _normal_stats_cache
    df = pd.read_csv(DATASET_PATH)
    normal = df[df["label"] == "NORMAL"]
    means = {f: float(normal[f].mean()) for f in features}
    stds = {f: max(1e-6, float(normal[f].std())) for f in features}
    _normal_stats_cache = (means, stds)
    return _normal_stats_cache


def _deviation_weighted(model, features, reading, top_n=5):
    means, stds = _normal_stats(features)
    importances = getattr(model, "feature_importances_", None)
    scores = {}
    for i, f in enumerate(features):
        z = abs(reading[f] - means[f]) / stds[f]
        weight = float(importances[i]) if importances is not None else 1.0
        scores[f] = z * weight
    ranked = sorted(scores.items(), key=lambda kv: -kv[1])[:top_n]
    total = sum(v for _, v in ranked) or 1.0
    return [
        {
            "feature": f,
            "score": round(v, 4),
            "share_pct": round(v / total * 100, 1),
            "live_value": round(float(reading[f]), 4),
            "normal_mean": round(means[f], 4),
        }
        for f, v in ranked
    ]


def _shap_rf(model, features, reading, top_n=5):
    try:
        vec = np.array([[reading[f] for f in features]])
        explainer = shap.TreeExplainer(model)
        sv = explainer.shap_values(vec)
        # sv is a list per class for multiclass RF; use the predicted class's row
        pred_idx = int(model.predict(vec)[0])
        if isinstance(sv, list):
            contribs = sv[pred_idx][0]
        else:
            contribs = sv[0]
        scores = {f: abs(float(contribs[i])) for i, f in enumerate(features)}
        ranked = sorted(scores.items(), key=lambda kv: -kv[1])[:top_n]
        total = sum(v for _, v in ranked) or 1.0
        means, _ = _normal_stats(features)
        return [
            {
                "feature": f,
                "score": round(v, 4),
                "share_pct": round(v / total * 100, 1),
                "live_value": round(float(reading[f]), 4),
                "normal_mean": round(means[f], 4),
            }
            for f, v in ranked
        ]
    except Exception:
        return None  # caller falls back


def explain(model, model_kind, features, reading, top_n=5):
    """model_kind: 'RF' | 'SVM' | 'MLP'. Returns a ranked list of the
    top_n contributing features plus which method produced it."""
    if model_kind == "RF" and _HAS_SHAP:
        result = _shap_rf(model, features, reading, top_n)
        if result is not None:
            return {"method": "shap_tree_explainer", "top_features": result}
    return {"method": "deviation_weighted", "top_features": _deviation_weighted(model, features, reading, top_n)}
