# Network Security: Phishing Website Detection

An end-to-end MLOps project that classifies websites as phishing or legitimate from 30 URL and page features. Training data lives in MongoDB, experiments are tracked with MLflow on DagsHub, and predictions are served by a FastAPI app that also runs as a Docker container.

## How it works

1. `push_data.py` loads `Network_Data/phisingData.csv` (11,055 rows) into MongoDB, database `AI`, collection `NetworkData`.
2. The training pipeline (`main.py`, or `GET /train` in the app) runs four stages and writes each run's outputs to `Artifacts/<timestamp>/`:
   1. **Ingestion:** reads the collection and splits it 80/20 into train and test sets.
   2. **Validation:** writes a drift report comparing train and test (Kolmogorov–Smirnov test per column).
   3. **Transformation:** fits a KNN imputer and maps the target from -1/1 to 0/1.
   4. **Training:** grid-searches Random Forest, Decision Tree, Gradient Boosting, Logistic Regression and AdaBoost, logs metrics and the best model to MLflow, and saves it to `final_model/`.
3. The FastAPI app (`app.py`) loads `final_model/` and scores uploaded CSV files, or a single URL whose features it computes itself.

## Requirements

- Python 3.10 to 3.13 (the pinned NumPy version has no Python 3.14 builds)
- A MongoDB database: a MongoDB Atlas cluster, or MongoDB running locally in Docker
- A DagsHub account and access token, for MLflow tracking during training
- Docker, if you want to run MongoDB or the app in containers

## Setup

```bash
python -m venv venv
venv\Scripts\activate          # Windows
source venv/bin/activate       # macOS / Linux
pip install -r requirements.txt
```

Copy `.env.example` to `.env` and fill in the values. `.env` is gitignored, so it never gets committed.

| Variable | What to put there |
| --- | --- |
| `MONGO_DB_URL`, `MONGODB_URL_KEY` | The same MongoDB connection string in both. For Atlas, URL-encode any special characters in the password (`@` becomes `%40`) and leave out the `< >` from the template. |
| `MLFLOW_TRACKING_URI`, `MLFLOW_TRACKING_USERNAME` | Your DagsHub MLflow URL and username |
| `MLFLOW_TRACKING_PASSWORD` | Your DagsHub access token |

To use a local MongoDB instead of Atlas:

```bash
docker run -d --name networksecurity-mongo -p 27017:27017 mongo:7
```

Then set both MongoDB variables to `mongodb://localhost:27017/`.

To check the connection:

```bash
python test_mongodb.py
```

## Load the data

```bash
python push_data.py
```

The last line printed should be `11055`. Run it only once: a second run inserts every record again, and the duplicates leak into both the train and test sets.

## Train

```bash
python main.py
```

This takes a few minutes. It updates `final_model/model.pkl` and `final_model/preprocessor.pkl`, creates a new folder under `Artifacts/`, and logs the runs to DagsHub.

## Run the API

```bash
python app.py
```

Open http://localhost:8000/docs. To score a file:

```bash
curl -X POST http://localhost:8000/predict -F "file=@valid_data/test.csv"
```

In Windows PowerShell, type `curl.exe` instead of `curl`.

The CSV needs exactly the 30 feature columns, without `Result`. The response is an HTML table with a `predicted_column` (1 or 0), and the same table is saved to `prediction_output/output.csv`.

`GET /train` runs the whole training pipeline inside the request, so the server is busy until it finishes.

### Check a single URL

`POST /predict-url` takes a link instead of a CSV:

```bash
curl -X POST http://localhost:8000/predict-url -H "Content-Type: application/json" -d '{"url": "https://github.com"}'
```

On Windows, the Swagger UI at `/docs` is easier than quoting JSON for curl. The response contains:

| Field | Meaning |
| --- | --- |
| `prediction` | `phishing` or `legitimate` |
| `phishing_probability` | The model's probability that the site is phishing, from 0 to 1 |
| `features` | All 30 feature values; `null` where a feature could not be measured |
| `filled_by_imputer` | The features the KNN imputer filled in from the most similar training rows |
| `notes` | Anything that limited the check, such as a page that could not be downloaded |

[networksecurity/components/url_feature_extraction.py](networksecurity/components/url_feature_extraction.py) computes the features with the dataset's published rules. It uses the URL text, the downloaded page (HTML only, JavaScript is never run), the site's certificate, DNS, the domain's registration date (RDAP), and its traffic rank (Tranco, which replaces the retired Alexa ranking). A check usually takes 2–6 seconds. Private and local addresses are never contacted, including through redirects.

Limits to keep in mind:

- **11 features are never measured.** Seven are coded in the training data in a way that contradicts their published rule, so computing them would mislead the model. The other four (`Page_Rank`, `Google_Index`, `Links_pointing_to_page`, `Statistical_report`) need services that no longer exist or need paid keys. The imputer fills all of them.
- **The training data is from 2012–2015.** The most important feature, `SSLfinal_State`, treated a trusted HTTPS certificate as a strong sign of a legitimate site. Most phishing sites now have free, valid certificates, so expect more phishing sites to slip through than the 97.6% test accuracy suggests.
- **It has only been tested on well-known sites and hand-made phishing-style URLs** (see [test_data/README.md](test_data/README.md)), not on live phishing sites.

## Run with Docker

```bash
docker build -t networksecurity .
docker run -d -p 8080:8000 --env-file .env --name networksecurity networksecurity
```

Open http://localhost:8080/docs. If `.env` points at a MongoDB on your own machine (`localhost`), add `-e MONGO_DB_URL=mongodb://host.docker.internal:27017/ -e MONGODB_URL_KEY=mongodb://host.docker.internal:27017/` to the `docker run` command, because `localhost` inside the container is the container itself.

## Testing

`test_data/` has CSV files for checking the API: a 2,211-row held-out set with expected labels, small phishing and legitimate samples, a sample with blank cells, two invalid files that should be rejected, and a list of URLs for `/predict-url`. With the app running:

```bash
python test_data/check_predictions.py
python test_data/check_urls.py
```

See [test_data/README.md](test_data/README.md) for every file and its expected result.

The unit tests in `tests/` check the URL feature rules without any network access:

```bash
pip install pytest
python -m pytest tests
```

## CI/CD

The GitHub Actions workflow in `.github/workflows/main.yml` runs on every push and pull request to `main`. It installs the requirements, compiles the code, runs the unit tests, runs the saved model on `valid_data/test.csv`, and builds the Docker image.

The workflow also contains jobs that push the image to Amazon ECR and run it on an EC2 instance through a self-hosted runner. They only run when started by hand from the Actions tab. The AWS resources for this project have been removed, so those jobs need new AWS secrets and a new runner before they can work.

## Project structure

```
app.py                     FastAPI app: /predict, /predict-url and /train
main.py                    Runs the training pipeline from the command line
push_data.py               Loads the CSV into MongoDB
test_mongodb.py            Checks the MongoDB connection
networksecurity/
  components/              Ingestion, validation, transformation, model training, URL feature extraction
  pipeline/                TrainingPipeline, which chains the stages
  entity/                  Config and artifact classes passed between stages
  constant/                File names, paths and thresholds
  utils/                   File helpers, metrics and the NetworkModel wrapper
  exception/, logging/     Custom exception and file logger
data_schema/schema.yaml    Expected columns
final_model/               Model and preprocessor used by the API
valid_data/test.csv        Sample input for /predict
test_data/                 CSV files, URLs and scripts for checking the API
tests/                     Unit tests (run with `python -m pytest tests`)
```
