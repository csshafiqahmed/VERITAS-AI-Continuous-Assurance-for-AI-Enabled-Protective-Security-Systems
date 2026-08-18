"""Training and loading for the laboratory security classifier."""

from __future__ import annotations

import platform
import time
from collections.abc import Callable
from importlib.metadata import version
from pathlib import Path
from typing import Any

import numpy as np
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler
from xgboost import XGBClassifier

from veritas_ai.constants import CLASSES, DEFAULT_SEED, FEATURES, SCHEMA_VERSION
from veritas_ai.io import read_json, read_jsonl, sha256_file, write_json
from veritas_ai.metrics import labelled_metrics


def matrix(records: list[dict[str, Any]]) -> np.ndarray:
    return np.asarray(
        [[float(record[name]) for name in FEATURES] for record in records], dtype=float
    )


def encoded_labels(records: list[dict[str, Any]]) -> np.ndarray:
    lookup = {name: index for index, name in enumerate(CLASSES)}
    return np.asarray([lookup[str(record["label"])] for record in records], dtype=int)


def train_model(
    dataset_path: Path,
    output: Path,
    seed: int = DEFAULT_SEED,
    progress: Callable[[str], None] | None = None,
) -> dict[str, Any]:
    records = read_jsonl(dataset_path)
    training = [record for record in records if record.get("split") == "train"]
    calibration = [record for record in records if record.get("split") == "calibration"]
    if not training or not calibration:
        raise ValueError("Dataset requires non-empty train and calibration splits")
    x_train = matrix(training)
    y_train = encoded_labels(training)
    x_calibration = matrix(calibration)
    y_calibration = encoded_labels(calibration)

    model = XGBClassifier(
        objective="multi:softprob",
        num_class=len(CLASSES),
        n_estimators=120,
        max_depth=4,
        learning_rate=0.08,
        subsample=0.8,
        colsample_bytree=0.8,
        reg_lambda=1.0,
        eval_metric="mlogloss",
        random_state=seed,
        n_jobs=1,
    )
    start = time.perf_counter()
    model.fit(x_train, y_train)
    training_seconds = time.perf_counter() - start
    probabilities = model.predict_proba(x_calibration)
    if progress is not None:
        progress("xgboost")

    comparison = make_pipeline(
        StandardScaler(),
        LogisticRegression(max_iter=1000, random_state=seed),
    )
    comparison.fit(x_train, y_train)
    comparison_probabilities = comparison.predict_proba(x_calibration)
    if progress is not None:
        progress("logistic_regression")

    output.mkdir(parents=True, exist_ok=True)
    model_path = output / "model.json"
    model.save_model(model_path)
    manifest: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "model_type": "XGBClassifier",
        "model_format": "native_xgboost_json",
        "model_sha256": sha256_file(model_path),
        "seed": seed,
        "features": FEATURES,
        "classes": CLASSES,
        "dataset_sha256": sha256_file(dataset_path),
        "dataset_observations": len(records),
        "training_observations": len(training),
        "calibration_observations": len(calibration),
        "training_seconds": training_seconds,
        "calibration_metrics": labelled_metrics(y_calibration, probabilities, CLASSES),
        "logistic_comparison_metrics": labelled_metrics(
            y_calibration, comparison_probabilities, CLASSES
        ),
        "environment": {
            "python": platform.python_version(),
            "xgboost": version("xgboost"),
            "scikit_learn": version("scikit-learn"),
            "numpy": version("numpy"),
        },
    }
    write_json(output / "model_manifest.json", manifest)
    return manifest


def load_model(model_dir: Path) -> tuple[XGBClassifier, dict[str, Any]]:
    manifest = read_json(model_dir / "model_manifest.json")
    model_path = model_dir / "model.json"
    if sha256_file(model_path) != manifest["model_sha256"]:
        raise ValueError("Model hash does not match its manifest")
    if manifest["features"] != FEATURES or manifest["classes"] != CLASSES:
        raise ValueError("Model feature or class contract is incompatible")
    model = XGBClassifier()
    model.load_model(model_path)
    return model, manifest


def predict(model: XGBClassifier, records: list[dict[str, Any]]) -> tuple[np.ndarray, float]:
    start = time.perf_counter()
    probabilities = model.predict_proba(matrix(records))
    latency_ms = (time.perf_counter() - start) * 1000
    return probabilities, latency_ms
