"""Send a CSV to the running API's /predict endpoint and compare the predictions with expected labels.

Usage:
    python test_data/check_predictions.py                       # held-out set against Docker (port 8080)
    python test_data/check_predictions.py --url http://localhost:8000   # against `python app.py`
    python test_data/check_predictions.py --features test_data/phishing_10.csv --expect 0
"""
import argparse
import re

import pandas as pd
import requests

parser = argparse.ArgumentParser()
parser.add_argument("--url", default="http://localhost:8080")
parser.add_argument("--features", default="test_data/holdout_2211.csv")
parser.add_argument("--labels", default="test_data/holdout_2211_labels.csv")
parser.add_argument("--expect", type=int, choices=[0, 1], help="expected label for every row (instead of --labels)")
args = parser.parse_args()

with open(args.features, "rb") as f:
    response = requests.post(f"{args.url}/predict", files={"file": f}, timeout=300)
print(f"POST /predict -> HTTP {response.status_code}")
response.raise_for_status()

# The API returns DataFrame.to_html(); predicted_column is the last cell of each row
rows = re.findall(r"<tr>\s*<th>\d+</th>(.*?)</tr>", response.text, re.S)
predicted = [int(float(re.findall(r"<td>(.*?)</td>", row)[-1])) for row in rows]

if args.expect is not None:
    expected = [args.expect] * len(predicted)
else:
    expected = pd.read_csv(args.labels)["expected"].tolist()

if len(predicted) != len(expected):
    raise SystemExit(f"Got {len(predicted)} predictions for {len(expected)} expected labels")

result = pd.crosstab(pd.Series(expected, name="expected"), pd.Series(predicted, name="predicted"))
correct = sum(p == e for p, e in zip(predicted, expected))
print(f"rows: {len(predicted)} | correct: {correct} | accuracy: {correct / len(predicted):.3f}")
print("(0 = phishing, 1 = legitimate)")
print(result)
