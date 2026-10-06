# Test data

CSV files for checking that the API and the model work. All rows come from the 20% test split of the training run that produced the model in `final_model/`, so the model never trained on them.

Predictions use **0 = phishing** and **1 = legitimate**. In the source dataset, `Result` is -1 for phishing and 1 for legitimate.

| File | Rows | What it tests | Expected result |
| --- | --- | --- | --- |
| `holdout_2211.csv` + `holdout_2211_labels.csv` | 2,211 | Overall accuracy on unseen rows | HTTP 200; about 97–98% correct |
| `phishing_10.csv` | 10 | Known phishing sites | HTTP 200; all or nearly all predicted 0 |
| `legitimate_10.csv` | 10 | Known legitimate sites | HTTP 200; all or nearly all predicted 1 |
| `missing_values_20.csv` + `missing_values_20_labels.csv` | 20 | 3 blank cells per row, filled by the KNN imputer | HTTP 200; a prediction for every row |
| `invalid_has_result_column.csv` | 5 | Input that still has the `Result` column | HTTP 500 (the model only accepts the 30 feature columns) |
| `invalid_missing_column.csv` | 5 | Input without `SSLfinal_State` | HTTP 500 |

## Running the checks

Start the app first, either with Docker (port 8080) or with `python app.py` (port 8000). Then run:

```bash
# Held-out set against Docker
python test_data/check_predictions.py

# Against `python app.py`
python test_data/check_predictions.py --url http://localhost:8000

# One label for every row
python test_data/check_predictions.py --features test_data/phishing_10.csv --expect 0
python test_data/check_predictions.py --features test_data/legitimate_10.csv --expect 1

# With a labels file
python test_data/check_predictions.py --features test_data/missing_values_20.csv --labels test_data/missing_values_20_labels.csv
```

The invalid files are checked by uploading them in the Swagger UI (`/docs` → `POST /predict` → **Try it out**) or with curl:

```bash
curl -X POST http://localhost:8080/predict -F "file=@test_data/invalid_missing_column.csv"
```

In Windows PowerShell, type `curl.exe` instead of `curl`.

If you retrain the model, the held-out files are no longer unseen by the new model, because each run makes a new random split. Its test split is in `Artifacts/<timestamp>/data_ingestion/ingested/test.csv`.

## Results with the current model

| File | Result |
| --- | --- |
| `holdout_2211.csv` | 2,158 of 2,211 correct (97.6%); 28 phishing sites predicted legitimate, 25 legitimate sites predicted phishing |
| `phishing_10.csv`, `legitimate_10.csv` | 10 of 10 correct each |
| `missing_values_20.csv` | 20 of 20 correct |
| Both invalid files | HTTP 500, with "The feature names should match those that were passed during fit" in the server log |
