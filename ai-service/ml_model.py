import os
import pickle
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline

MODEL_PATH = os.path.join(os.path.dirname(__file__), "phishing_model.pkl")

# Mini dataset of phishing and ham emails for PoC training
TRAINING_DATA = [
    # Phishing (label 1)
    ("Urgent: Confirm your bank account details immediately to prevent suspension.", 1),
    ("Your PayPal account has been restricted. Click here to verify your identity.", 1),
    ("Dear customer, we detected unusual login activity. Reset password now.", 1),
    ("Netflix Payment Declined: Update your billing info within 24 hours.", 1),
    ("Congratulations! You won a $1000 Amazon gift card. Claim your prize now.", 1),
    ("Verify your Office 365 credentials. Critical security update required.", 1),
    ("Invoice PDF attached. Click link to view and pay outstanding balance.", 1),
    ("Google Account Alert: Someone has your password. Secure account immediately.", 1),
    ("IRS Tax Refund: Submit your banking details to claim your refund online.", 1),
    ("Security Alert: Unauthorized access attempt detected. Click to lock account.", 1),
    
    # Ham (label 0)
    ("Hi team, here is the agenda for our weekly sync meeting tomorrow morning.", 0),
    ("Thanks for sending the report. I will review it and get back to you.", 0),
    ("Are we still on for lunch at 12:30 PM today? Let me know.", 0),
    ("Please find the updated project timeline attached for your reference.", 0),
    ("Let's reschedule our design review to next Tuesday afternoon.", 0),
    ("Congratulations on completing the training course! Well done.", 0),
    ("Can you review this PR and approve it if it looks good?", 0),
    ("Here are the notes from yesterday's product brainstorming session.", 0),
    ("The office will be closed on Friday for the national holiday.", 0),
    ("Just checking if you had a chance to look at the budget proposal.", 0)
]

def train_model():
    """Trains a simple TF-IDF + Logistic Regression model and pickles it."""
    texts = [item[0] for item in TRAINING_DATA]
    labels = [item[1] for item in TRAINING_DATA]
    
    # Simple Pipeline
    pipeline = Pipeline([
        ('tfidf', TfidfVectorizer(stop_words='english', lowercase=True)),
        ('clf', LogisticRegression(C=1.0))
    ])
    
    pipeline.fit(texts, labels)
    
    # Save the pipeline
    with open(MODEL_PATH, 'wb') as f:
        pickle.dump(pipeline, f)
    print("Model trained and saved successfully.")
    return pipeline

def get_model():
    """Loads the model, training it first if not found."""
    if not os.path.exists(MODEL_PATH):
        return train_model()
    
    with open(MODEL_PATH, 'rb') as f:
        return pickle.load(f)

def predict_phishing(text: str) -> float:
    """Predicts the probability of text being phishing."""
    try:
        model = get_model()
        # Return probability of class 1 (phishing)
        probs = model.predict_proba([text])[0]
        # class 0 prob is probs[0], class 1 prob is probs[1]
        return float(probs[1])
    except Exception as e:
        print(f"Error in prediction: {e}")
        # Fallback to simple keyword ratio if model fails
        keywords = ["urgent", "verify", "suspend", "paypal", "netflix", "bank", "click", "reset", "password", "login", "invoice"]
        count = sum(1 for kw in keywords if kw in text.lower())
        return min(0.99, count * 0.15)

if __name__ == "__main__":
    # If run directly, train the model
    train_model()
    # Test prediction
    test_phish = "URGENT: Click here to reset your bank password!"
    test_ham = "Let's grab a coffee at 2 PM today."
    print(f"Phishing probability for: '{test_phish}' -> {predict_phishing(test_phish):.2f}")
    print(f"Phishing probability for: '{test_ham}' -> {predict_phishing(test_ham):.2f}")
