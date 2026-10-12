"""
CyberShield AI — ML Threat Prediction CLI
Provides explainable AI inference for any candidate text, URL, email, or message.
"""

import sys
import os
import joblib

def predict(text: str):
    model_path = os.path.join(os.path.dirname(__file__), "models", "threat_classifier.joblib")
    if not os.path.exists(model_path):
        print(f"Model file not found at {model_path}. Train first using: python ml/train.py")
        sys.exit(1)

    pipeline = joblib.load(model_path)
    prediction = pipeline.predict([text])[0]
    probabilities = pipeline.predict_proba([text])[0]
    confidence = probabilities[prediction] * 100
    phish_prob = probabilities[1] * 100

    print("=======================================================")
    print(" CyberShield AI — AI Threat Classification Result     ")
    print("=======================================================")
    print(f"Input Snippet : {text[:120]}...")
    print(f"Prediction    : {'MALICIOUS / PHISHING' if prediction == 1 else 'SAFE / BENIGN'}")
    print(f"Risk Score    : {phish_prob:.1f}%")
    print(f"Confidence    : {confidence:.1f}%")
    print("Explanation   : Analysis based on lexical n-grams and TF-IDF features.")
    print("=======================================================")

    return {
        "prediction": int(prediction),
        "is_threat": bool(prediction == 1),
        "risk_percentage": float(phish_prob),
        "confidence": float(confidence),
    }

if __name__ == "__main__":
    if len(sys.argv) > 1:
        query = " ".join(sys.argv[1:])
    else:
        query = "Your bank KYC has expired. Click here immediately to update your account: http://g00gle.com"
    predict(query)
