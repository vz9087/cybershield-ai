"""
CyberShield AI — Machine Learning Model Training Script
Trains a TF-IDF + Logistic Regression / Naive Bayes classifier on cybersecurity threat data.
Outputs genuine measured metrics (Accuracy, Precision, Recall, F1-Score).
Saves model assets to ml/models/threat_classifier.joblib.
"""

import os
import joblib
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, classification_report
from dataset import get_dataset

def train_model():
    texts, labels = get_dataset()

    X_train, X_test, y_train, y_test = train_test_split(
        texts, labels, test_size=0.25, random_state=42, stratify=labels
    )

    pipeline = Pipeline([
        ("tfidf", TfidfVectorizer(ngram_range=(1, 2), min_df=1, sublinear_tf=True)),
        ("classifier", LogisticRegression(C=1.0, max_iter=200, random_state=42)),
    ])

    pipeline.fit(X_train, y_train)

    y_pred = pipeline.predict(X_test)

    accuracy = accuracy_score(y_test, y_pred)
    precision = precision_score(y_test, y_pred, zero_division=0)
    recall = recall_score(y_test, y_pred, zero_division=0)
    f1 = f1_score(y_test, y_pred, zero_division=0)

    print("=======================================================")
    print(" CyberShield AI — ML Threat Detection Engine Training ")
    print("=======================================================")
    print(f"Total Samples    : {len(texts)}")
    print(f"Training Set Size: {len(X_train)}")
    print(f"Test Set Size    : {len(X_test)}")
    print("-------------------------------------------------------")
    print(f"Measured Accuracy : {accuracy * 100:.2f}%")
    print(f"Measured Precision: {precision * 100:.2f}%")
    print(f"Measured Recall   : {recall * 100:.2f}%")
    print(f"Measured F1-Score : {f1 * 100:.2f}%")
    print("-------------------------------------------------------")
    print("Classification Report:")
    print(classification_report(y_test, y_pred, target_names=["Safe", "Malicious/Phishing"], zero_division=0))
    print("=======================================================")

    models_dir = os.path.join(os.path.dirname(__file__), "models")
    os.makedirs(models_dir, exist_ok=True)
    model_path = os.path.join(models_dir, "threat_classifier.joblib")
    joblib.dump(pipeline, model_path)
    print(f"Model successfully saved to: {model_path}")

    return {
        "accuracy": accuracy,
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "model_path": model_path
    }

if __name__ == "__main__":
    train_model()
