from pathlib import Path
import sys

import joblib
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, f1_score, precision_score, recall_score
from sklearn.model_selection import train_test_split

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from ml.dataset_generator import OUTPUT_PATH, generate_dataset


BASE_DIR = Path(__file__).resolve().parent
MODEL_PATH = BASE_DIR / "random_forest_ids.joblib"
METRICS_PATH = BASE_DIR / "model_metrics.txt"
FEATURE_COLUMNS = ["login_hour", "preceding_fails", "suspicious_ip", "country_mismatch", "new_device"]


def train_model(dataset_path: Path = OUTPUT_PATH, model_path: Path = MODEL_PATH, metrics_path: Path = METRICS_PATH) -> dict[str, float]:
    if not dataset_path.exists():
        generate_dataset(output_path=dataset_path)

    frame = pd.read_csv(dataset_path)
    x_train, x_test, y_train, y_test = train_test_split(
        frame[FEATURE_COLUMNS],
        frame["is_intrusion"],
        test_size=0.25,
        random_state=42,
        stratify=frame["is_intrusion"],
    )
    model = RandomForestClassifier(
        n_estimators=180,
        max_depth=8,
        min_samples_leaf=4,
        class_weight="balanced",
        random_state=42,
        n_jobs=-1,
    )
    model.fit(x_train, y_train)
    predictions = model.predict(x_test)
    metrics = {
        "accuracy": accuracy_score(y_test, predictions),
        "precision": precision_score(y_test, predictions, zero_division=0),
        "recall": recall_score(y_test, predictions, zero_division=0),
        "f1": f1_score(y_test, predictions, zero_division=0),
    }
    model_path.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(model, model_path)
    metrics_path.write_text(
        "\n".join(f"{name}: {value:.4f}" for name, value in metrics.items()) + "\n",
        encoding="utf-8",
    )
    return metrics


if __name__ == "__main__":
    result = train_model()
    print("Trained Random Forest IDS model")
    for key, value in result.items():
        print(f"{key}: {value:.4f}")
