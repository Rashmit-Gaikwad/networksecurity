import sys
import os

import certifi
ca = certifi.where()

from dotenv import load_dotenv
load_dotenv()
mongo_db_url = os.getenv("MONGODB_URL_KEY")
import pymongo
from networksecurity.exception.exception import NetworkSecurityException
from networksecurity.logging.logger import logging
from networksecurity.pipeline.training_pipeline import TrainingPipeline

from fastapi.middleware.cors import CORSMiddleware
from fastapi import FastAPI, File, UploadFile,Request,HTTPException
from pydantic import BaseModel
from uvicorn import run as app_run
from fastapi.responses import Response
from starlette.responses import RedirectResponse
import pandas as pd

from networksecurity.utils.main_utils.utils import load_object

from networksecurity.utils.ml_utils.model.estimator import NetworkModel
from networksecurity.components.url_feature_extraction import URLFeatureExtractor


client = pymongo.MongoClient(mongo_db_url, tlsCAFile=ca)

from networksecurity.constant.training_pipeline import DATA_INGESTION_COLLECTION_NAME
from networksecurity.constant.training_pipeline import DATA_INGESTION_DATABASE_NAME

database = client[DATA_INGESTION_DATABASE_NAME]
collection = database[DATA_INGESTION_COLLECTION_NAME]

app = FastAPI()
origins = ["*"]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

from fastapi.templating import Jinja2Templates
templates = Jinja2Templates(directory="./templates")

@app.get("/", tags=["authentication"])
async def index():
    return RedirectResponse(url="/docs")

@app.get("/train")
async def train_route():
    try:
        train_pipeline=TrainingPipeline()
        train_pipeline.run_pipeline()
        return Response("Training is successful")
    except Exception as e:
        raise NetworkSecurityException(e,sys)
    
@app.post("/predict")
async def predict_route(request: Request, file: UploadFile = File(...)):
    try:
        df = pd.read_csv(file.file)
        preprocesor = load_object("final_model/preprocessor.pkl")
        final_model = load_object("final_model/model.pkl")
        network_model = NetworkModel(preprocessor=preprocesor, model=final_model)
        print(df.iloc[0])
        y_pred = network_model.predict(df)
        print(y_pred)
        df['predicted_column'] = y_pred
        print(df['predicted_column'])
        df.to_csv('prediction_output/output.csv')
        table_html = df.to_html(classes='table table-striped')
        return Response(content=table_html, media_type="text/html")
    except Exception as e:
        raise NetworkSecurityException(e, sys)
        
    except Exception as e:
            raise NetworkSecurityException(e,sys)


class URLRequest(BaseModel):
    url: str


## A plain def so FastAPI runs it in a worker thread: downloading the page blocks
@app.post("/predict-url")
def predict_url_route(request: URLRequest):
    try:
        check = URLFeatureExtractor().extract(request.url)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    try:
        preprocessor = load_object("final_model/preprocessor.pkl")
        final_model = load_object("final_model/model.pkl")
        ## Unmeasured features are NaN; the KNN imputer fills them from the most similar training rows
        row = pd.DataFrame([check.features], columns=preprocessor.feature_names_in_, dtype=float)
        features = preprocessor.transform(row)
        predicted = int(final_model.predict(features)[0])
        phishing_probability = float(final_model.predict_proba(features)[0][list(final_model.classes_).index(0)])
        return {
            "url": check.url,
            "final_url": check.final_url,
            "prediction": "legitimate" if predicted == 1 else "phishing",
            "phishing_probability": round(phishing_probability, 3),
            "features": check.features,
            "filled_by_imputer": [name for name, value in check.features.items() if value is None],
            "notes": check.notes,
        }
    except Exception as e:
        raise NetworkSecurityException(e, sys)


if __name__=="__main__":
    app_run(app,host="0.0.0.0",port=8000)




