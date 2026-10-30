"""
tests/test_models.py
=======================
Loads each saved model (RF, SVM, MLP) and asserts it predicts on a
sample feature vector without error and outputs a valid class label.

Requires `python train_models.py` to have been run first (as the
README instructs) so model_rf.pkl / model_svm.pkl / model_mlp.pkl
exist in backend/.
"""

import os
import sys
import pickle

import numpy as np
import pytest

BACKEND_DIR = os.path.join(os.path.dirname(__file__), "..", "backend")
sys.path.insert(0, BACKEND_DIR)

from attacks import CLASSES, normal_readings, clip  # noqa: E402

MODEL_FILES = ["model_rf.pkl", "model_svm.pkl", "model_mlp.pkl"]


def _model_path(filename):
    return os.path.join(BACKEND_DIR, filename)


@pytest.mark.parametrize("filename", MODEL_FILES)
def test_model_file_exists(filename):
    path = _model_path(filename)
    if not os.path.exists(path):
        pytest.skip(f"{filename} not found - run `python train_models.py` first.")
    assert os.path.getsize(path) > 0


@pytest.mark.parametrize("filename", MODEL_FILES)
def test_model_predicts_valid_class_on_sample_vector(filename):
    path = _model_path(filename)
    if not os.path.exists(path):
        pytest.skip(f"{filename} not found - run `python train_models.py` first.")

    with open(path, "rb") as f:
        bundle = pickle.load(f)

    model = bundle["model"]
    features = bundle["features"]
    le = bundle["label_encoder"]

    sample = clip(normal_readings(42))
    vec = np.array([[sample[f] for f in features]])
    if "scaler" in bundle:
        vec = bundle["scaler"].transform(vec)

    pred_idx = model.predict(vec)[0]
    pred_class = le.inverse_transform([pred_idx])[0]

    assert pred_class in CLASSES

    probs = model.predict_proba(vec)[0]
    assert len(probs) == len(le.classes_)
    assert abs(sum(probs) - 1.0) < 1e-3
