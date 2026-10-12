import os
import sys
import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from dataset import get_dataset
from predict import predict
from train import train_model

def test_dataset_integrity():
    texts, labels = get_dataset()
    assert len(texts) > 0
    assert len(texts) == len(labels)
    assert set(labels) == {0, 1}

def test_training_and_model_creation():
    results = train_model()
    assert results["accuracy"] > 0.70
    assert results["f1"] > 0.70
    assert os.path.exists(results["model_path"])

def test_predict_phishing():
    res = predict("URGENT: Your bank account is blocked. Share your OTP now.")
    assert res["is_threat"] is True
    assert res["risk_percentage"] > 50.0

def test_predict_benign():
    res = predict("Team meeting is scheduled for tomorrow morning in conference room 3.")
    assert res["is_threat"] is False
