from pathlib import Path

import numpy as np
import pandas as pd


OUTPUT_PATH = Path(__file__).resolve().parent / "synthetic_auth_events.csv"


def generate_dataset(rows: int = 5000, output_path: Path = OUTPUT_PATH, seed: int = 42) -> Path:
    rng = np.random.default_rng(seed)
    login_hour = rng.integers(0, 24, rows)
    preceding_fails = rng.poisson(1.2, rows).clip(0, 10)
    suspicious_ip = rng.binomial(1, 0.18, rows)
    country_mismatch = rng.binomial(1, 0.12, rows)
    new_device = rng.binomial(1, 0.30, rows)
    off_hours = ((login_hour < 6) | (login_hour > 22)).astype(int)

    risk_signal = (
        0.18 * off_hours
        + 0.12 * preceding_fails
        + 0.24 * suspicious_ip
        + 0.22 * country_mismatch
        + 0.10 * new_device
        + rng.normal(0, 0.08, rows)
    )
    is_intrusion = (risk_signal > 0.48).astype(int)
    frame = pd.DataFrame(
        {
            "login_hour": login_hour,
            "preceding_fails": preceding_fails,
            "suspicious_ip": suspicious_ip,
            "country_mismatch": country_mismatch,
            "new_device": new_device,
            "is_intrusion": is_intrusion,
        }
    )
    output_path.parent.mkdir(parents=True, exist_ok=True)
    frame.to_csv(output_path, index=False)
    return output_path


if __name__ == "__main__":
    path = generate_dataset()
    print(f"Generated synthetic IDS dataset at {path}")
