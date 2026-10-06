# Network Security: Phishing Website Detection

An end-to-end MLOps project that classifies websites as phishing or legitimate from 30 URL and page features. Training data lives in MongoDB, experiments are tracked with MLflow on DagsHub, and predictions are served by a FastAPI app that also runs as a Docker container.

## How it works

1. `push_data.py` loads `Network_Data/phisingData.csv` (11,055 rows) into MongoDB, database `AI`, collection `NetworkData`.
2. The training pipeline (`main.py`, or `GET /train` in the app) runs four stages and writes each run's outputs to `Artifacts/<timestamp>/`:
   1. **Ingestion:** reads the collection and splits it 80/20 into train and test sets.
   2. **Validation:** writes a drift report comparing train and test (Kolmogorov–Smirnov test per column).
   3. **Transformation:** fits a KNN imputer and maps the target from -1/1 to 0/1.
   4. **Training:** grid-searches Random Forest, Decision Tree, Gradient Boosting, Logistic Regression and AdaBoost, logs metrics and the best model to MLflow, and saves it to `final_model/`.
3. The FastAPI app (`app.py`) loads `final_model/` and scores uploaded CSV files.

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

## Run with Docker

```bash
docker build -t networksecurity .
docker run -d -p 8080:8000 --env-file .env --name networksecurity networksecurity
```

Open http://localhost:8080/docs. If `.env` points at a MongoDB on your own machine (`localhost`), add `-e MONGO_DB_URL=mongodb://host.docker.internal:27017/ -e MONGODB_URL_KEY=mongodb://host.docker.internal:27017/` to the `docker run` command, because `localhost` inside the container is the container itself.

## CI/CD

The GitHub Actions workflow in `.github/workflows/main.yml` runs on every push and pull request to `main`. It installs the requirements, compiles the code, runs the saved model on `valid_data/test.csv`, and builds the Docker image.

The workflow also contains jobs that push the image to Amazon ECR and run it on an EC2 instance through a self-hosted runner. They only run when started by hand from the Actions tab. The AWS resources for this project have been removed, so those jobs need new AWS secrets and a new runner before they can work.

## Project structure

```
app.py                     FastAPI app: /predict and /train
main.py                    Runs the training pipeline from the command line
push_data.py               Loads the CSV into MongoDB
test_mongodb.py            Checks the MongoDB connection
networksecurity/
  components/              Ingestion, validation, transformation, model training
  pipeline/                TrainingPipeline, which chains the stages
  entity/                  Config and artifact classes passed between stages
  constant/                File names, paths and thresholds
  utils/                   File helpers, metrics and the NetworkModel wrapper
  exception/, logging/     Custom exception and file logger
data_schema/schema.yaml    Expected columns
final_model/               Model and preprocessor used by the API
valid_data/test.csv        Sample input for /predict
```
