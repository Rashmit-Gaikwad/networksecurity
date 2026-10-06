"""Send every URL in a CSV to the running API's /predict-url endpoint and compare with the expected result.

Usage:
    python test_data/check_urls.py                                  # against Docker (port 8080)
    python test_data/check_urls.py --url http://localhost:8000      # against `python app.py`
"""
import argparse
import time

import pandas as pd
import requests

parser = argparse.ArgumentParser()
parser.add_argument("--url", default="http://localhost:8080")
parser.add_argument("--file", default="test_data/urls_to_check.csv")
args = parser.parse_args()

rows = []
for case in pd.read_csv(args.file).itertuples():
    started = time.time()
    response = requests.post(f"{args.url}/predict-url", json={"url": case.url}, timeout=120)
    result = response.json() if response.ok else {}
    rows.append({
        "url": case.url if len(case.url) <= 60 else case.url[:57] + "...",
        "expected": case.expected,
        "predicted": result.get("prediction", f"HTTP {response.status_code}"),
        "p(phishing)": result.get("phishing_probability"),
        "measured": 30 - len(result.get("filled_by_imputer", range(30))),
        "seconds": round(time.time() - started, 1),
    })
    time.sleep(1)  # the Tranco traffic-rank API allows about one request per second

table = pd.DataFrame(rows)
table["ok"] = table["expected"] == table["predicted"]
with pd.option_context("display.width", 200, "display.max_colwidth", 60):
    print(table.to_string(index=False))
print(f"\n{table['ok'].sum()} of {len(table)} as expected")
for expected, group in table.groupby("expected"):
    print(f"  {expected}: {group['ok'].sum()} of {len(group)}")
