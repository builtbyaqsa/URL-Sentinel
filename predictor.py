from pathlib import Path
import pickle

import pandas as pd

from feature_extractor import extract_features


MODEL_PATH = Path(__file__).resolve().parent / "phishing_model.pkl"

with open(MODEL_PATH, "rb") as file:
    saved_data = pickle.load(file)

model = saved_data["model"]
feature_names = saved_data["features"]


def predict_url(url):

    features = extract_features(url)

    X = pd.DataFrame([features])[feature_names]

    prediction = int(model.predict(X)[0])

    probabilities = model.predict_proba(X)[0]

    phishing_index = list(model.classes_).index(0)

    phishing_probability = float(
        probabilities[phishing_index]
    )

    result = {
        "url": url,
        "prediction": (
            "Phishing" if prediction == 0 else "Legitimate"
        ),
        "phishing_probability": round(
            phishing_probability, 4
        ),
        "risk_score": round(
            phishing_probability * 100, 2
        ),
        "source": "Random Forest ML Model"
    }

    return result