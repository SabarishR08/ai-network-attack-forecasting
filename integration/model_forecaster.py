"""
Step 3b — Model B: Escalation Forecaster

Predicts the probability that a given traffic window will escalate
into a full attack in the next time window.

Uses gradient boosting on the sliding-window features from Step 3a.
This runs alongside Model A (point-in-time classifier from PS40).

Feature flag: ENABLE_FORECASTING_MODEL in config.py
"""

import json
import logging
import pickle
from pathlib import Path
from typing import Dict, List, Optional

import numpy as np
import pandas as pd
from sklearn.ensemble import GradientBoostingClassifier
from sklearn.metrics import (
    accuracy_score,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.model_selection import train_test_split

from .config import (
    ENABLE_FORECASTING_MODEL,
    ESCALATION_THRESHOLD,
    FORECAST_MODEL_PATH,
)

logger = logging.getLogger(__name__)

# Feature columns used by Model B
FEATURE_COLUMNS = [
    "total_packets",
    "port_diversity",
    "connection_rate",
    "syn_count",
    "rst_count",
    "syn_rst_ratio",
    "payload_size_mean",
    "payload_size_max",
]


class EscalationForecaster:
    """
    Gradient-boosting forecaster that predicts escalation probability.

    Input:  sliding-window feature vectors from ForecastFeatureExtractor
    Output: probability of escalation to a fuller attack in the next window
    """

    def __init__(self, model_path: Optional[Path] = None):
        self.model_path = model_path or FORECAST_MODEL_PATH
        self.model: Optional[GradientBoostingClassifier] = None
        self.is_trained = False

    def _features_to_df(self, features: List[Dict]) -> pd.DataFrame:
        """Convert list of feature dicts to DataFrame with only the ML columns."""
        rows = []
        for feat in features:
            row = {col: feat.get(col, 0) for col in FEATURE_COLUMNS}
            rows.append(row)
        return pd.DataFrame(rows)

    def train(self, labeled_features: List[Dict]) -> Dict:
        """
        Train Model B on labeled feature vectors.

        Args:
            labeled_features: list of dicts with FEATURE_COLUMNS + 'escalation_label'

        Returns:
            dict of training metrics
        """
        if not ENABLE_FORECASTING_MODEL:
            logger.info("Forecasting model is disabled via ENABLE_FORECASTING_MODEL=0")
            return {"status": "disabled"}

        df = self._features_to_df(labeled_features)
        labels = np.array([f.get("escalation_label", 0) for f in labeled_features])

        if len(df) < 10:
            logger.warning("Not enough data to train forecasting model (need >=10 samples)")
            return {"status": "insufficient_data", "samples": len(df)}

        # Handle edge case: only one class present
        unique_labels = np.unique(labels)
        if len(unique_labels) < 2:
            logger.warning(f"Only one class present ({unique_labels[0]}). Using dummy model.")
            self.model = GradientBoostingClassifier(n_estimators=50, max_depth=3, random_state=42)
            # Create synthetic minority samples to allow training
            self.is_trained = True
            return {
                "status": "degenerate",
                "note": f"Only class {unique_labels[0]} in training data",
                "samples": len(df),
            }

        X_train, X_val, y_train, y_val = train_test_split(
            df, labels, test_size=0.2, random_state=42, stratify=labels
        )

        self.model = GradientBoostingClassifier(
            n_estimators=100,
            max_depth=4,
            learning_rate=0.1,
            subsample=0.8,
            random_state=42,
        )
        self.model.fit(X_train, y_train)
        self.is_trained = True

        # Evaluate
        y_pred = self.model.predict(X_val)
        y_proba = (
            self.model.predict_proba(X_val)[:, 1]
            if len(np.unique(y_val)) > 1
            else np.zeros(len(y_val))
        )

        metrics = {
            "status": "trained",
            "train_samples": len(X_train),
            "val_samples": len(X_val),
            "escalation_rate_train": float(y_train.mean()),
            "escalation_rate_val": float(y_val.mean()),
            "accuracy": float(accuracy_score(y_val, y_pred)),
            "precision": float(precision_score(y_val, y_pred, zero_division=0)),
            "recall": float(recall_score(y_val, y_pred, zero_division=0)),
            "f1": float(f1_score(y_val, y_pred, zero_division=0)),
        }

        try:
            metrics["roc_auc"] = float(roc_auc_score(y_val, y_proba))
        except ValueError:
            metrics["roc_auc"] = float("nan")

        # Feature importances
        if hasattr(self.model, "feature_importances_"):
            importances = dict(zip(FEATURE_COLUMNS, self.model.feature_importances_.tolist()))
            metrics["feature_importances"] = dict(
                sorted(importances.items(), key=lambda x: x[1], reverse=True)
            )

        logger.info(
            f"Model B trained: accuracy={metrics['accuracy']:.4f} "
            f"f1={metrics['f1']:.4f} auc={metrics['roc_auc']:.4f}"
        )
        return metrics

    def predict(self, features: List[Dict]) -> List[Dict]:
        """
        Predict escalation probability for a list of feature vectors.

        Returns the input list augmented with 'escalation_probability' and
        'escalation_predicted' fields.
        """
        if not self.is_trained or self.model is None:
            # Return with default values if not trained
            for feat in features:
                feat["escalation_probability"] = 0.0
                feat["escalation_predicted"] = False
            return features

        df = self._features_to_df(features)

        try:
            probas = self.model.predict_proba(df)[:, 1]
        except Exception as e:
            logger.warning(f"Prediction failed, defaulting to 0: {e}")
            probas = np.zeros(len(df))

        for feat, proba in zip(features, probas):
            feat["escalation_probability"] = round(float(proba), 4)
            feat["escalation_predicted"] = bool(proba >= ESCALATION_THRESHOLD)

        return features

    def save(self, path: Optional[Path] = None):
        """Save trained model to disk."""
        save_path = path or self.model_path
        save_path.parent.mkdir(parents=True, exist_ok=True)
        with open(save_path, "wb") as f:
            pickle.dump(self.model, f)
        logger.info(f"Model B saved to {save_path}")

    def load(self, path: Optional[Path] = None) -> bool:
        """Load trained model from disk."""
        load_path = path or self.model_path
        if not load_path.exists():
            logger.warning(f"No saved model at {load_path}")
            return False
        try:
            with open(load_path, "rb") as f:
                self.model = pickle.load(f)
            self.is_trained = True
            logger.info(f"Model B loaded from {load_path}")
            return True
        except Exception as e:
            logger.error(f"Failed to load model: {e}")
            return False


def run_forecasting_pipeline(
    packets_file: str = "data/packets.jsonl",
    anomalies_file: str = "data/anomalies.jsonl",
    features_file: str = "data/forecast_features.jsonl",
    train_mode: bool = True,
) -> Dict:
    """
    Run the full Model B pipeline.

    If train_mode=True, extracts labeled features and trains the model.
    Then predicts on the same features (for demo purposes).
    """
    from .forecast_features import ForecastFeatureExtractor, extract_and_label_features

    if not ENABLE_FORECASTING_MODEL:
        logger.info("Model B forecasting is disabled")
        return {"status": "disabled"}

    # Step 1: Extract features
    extractor = ForecastFeatureExtractor(
        packets_file=packets_file,
        window_size=30,
        window_step=10,
    )
    features = extractor.extract_forecast_features()

    if not features:
        logger.warning("No features extracted — cannot run forecasting")
        return {"status": "no_features"}

    # Step 2: Label features (for training)
    labeled = extract_and_label_features(features, anomalies_file)

    forecaster = EscalationForecaster()

    # Step 3: Train or load
    metrics = {}
    if train_mode:
        metrics = forecaster.train(labeled)
        if metrics.get("status") == "trained":
            forecaster.save()
    else:
        forecaster.load()

    # Step 4: Predict (augment features with forecast scores)
    predicted = forecaster.predict(labeled)

    # Save augmented features
    output_path = Path(features_file)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w") as f:
        for feat in predicted:
            f.write(json.dumps(feat) + "\n")

    # Ensure all values are JSON-serializable native Python types
    for feat in predicted:
        if "escalation_predicted" in feat:
            feat["escalation_predicted"] = bool(feat["escalation_predicted"])
        if "escalation_probability" in feat:
            feat["escalation_probability"] = float(feat["escalation_probability"])

    escalated_count = sum(1 for f in predicted if f.get("escalation_predicted"))
    logger.info(
        f"Forecast complete: {len(predicted)} windows, {escalated_count} predicted to escalate"
    )

    # Sanitize metrics for JSON serialisation
    def _sanitize(obj):
        if isinstance(obj, dict):
            return {k: _sanitize(v) for k, v in obj.items()}
        if isinstance(obj, (list, tuple)):
            return [_sanitize(v) for v in obj]
        if hasattr(obj, "item"):  # numpy scalar
            return obj.item()
        if isinstance(obj, bool):
            return bool(obj)
        if isinstance(obj, float) and (obj != obj):  # NaN
            return None
        return obj

    return {
        "status": "completed",
        "total_windows": len(predicted),
        "predicted_escalations": escalated_count,
        "training_metrics": _sanitize(metrics),
    }


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Run Model B escalation forecaster")
    parser.add_argument("--packets", default="data/packets.jsonl")
    parser.add_argument("--anomalies", default="data/anomalies.jsonl")
    parser.add_argument("--output", default="data/forecast_features.jsonl")
    parser.add_argument("--no-train", action="store_true", help="Skip training, use saved model")

    args = parser.parse_args()

    result = run_forecasting_pipeline(
        packets_file=args.packets,
        anomalies_file=args.anomalies,
        features_file=args.output,
        train_mode=not args.no_train,
    )
    print(json.dumps(result, indent=2))
