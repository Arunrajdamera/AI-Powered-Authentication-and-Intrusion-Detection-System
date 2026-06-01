from pathlib import Path

import joblib
import numpy as np
import pandas as pd


FEATURE_COLUMNS = ["login_hour", "preceding_fails", "suspicious_ip", "country_mismatch", "new_device"]


class IntrusionPredictor:
    def __init__(self, model_path: str | Path):
        self.model_path = Path(model_path)
        self.model = None
        self.load_error = ""
        self._load()

    def _load(self) -> None:
        try:
            if self.model_path.exists():
                self.model = joblib.load(self.model_path)
        except (OSError, ValueError, EOFError) as exc:
            self.model = None
            self.load_error = str(exc)

    def predict_risk(self, features: list[float]) -> float:
        if self.model is None:
            return self._fallback_risk(features)
        try:
            sample = pd.DataFrame([np.array(features, dtype=float)], columns=FEATURE_COLUMNS)
            if hasattr(self.model, "predict_proba"):
                probabilities = self.model.predict_proba(sample)[0]
                return float(probabilities[-1])
            return float(self.model.predict(sample)[0])
        except (ValueError, TypeError, IndexError):
            return self._fallback_risk(features)

    @staticmethod
    def _fallback_risk(features: list[float]) -> float:
        login_hour, preceding_fails, suspicious_ip, country_mismatch, new_device = features[:5]
        score = 0.08
        if login_hour < 6 or login_hour > 22:
            score += 0.18
        score += min(preceding_fails * 0.12, 0.36)
        score += 0.22 if suspicious_ip else 0.0
        score += 0.18 if country_mismatch else 0.0
        score += 0.10 if new_device else 0.0
        return max(0.0, min(score, 0.99))
