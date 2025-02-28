import pickle
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler
import joblib
from datetime import datetime
import os

class PhishingDetectionModel:
    def __init__(self):
        """Initialize the phishing detection model with advanced configuration."""
        self.model = RandomForestClassifier(
            n_estimators=200,
            max_depth=15,
            min_samples_split=5,
            min_samples_leaf=2,
            max_features='sqrt',
            bootstrap=True,
            random_state=42,
            class_weight='balanced',
            n_jobs=-1
        )
        self.scaler = StandardScaler()
        self._train_initial_model()

    def _train_initial_model(self):
        """Train an advanced model with synthetic data."""
        np.random.seed(42)
        n_samples = 2000

        # Generate synthetic features (23 features as per updated feature extractor)
        X = np.random.rand(n_samples, 23)

        # Adjust feature distributions to be more realistic
        # URL length (0-255 characters)
        X[:, 0] = np.random.normal(loc=50, scale=30, size=n_samples)
        X[:, 0] = np.clip(X[:, 0], 0, 255)

        # Domain length (3-63 characters)
        X[:, 1] = np.random.normal(loc=15, scale=5, size=n_samples)
        X[:, 1] = np.clip(X[:, 1], 3, 63)

        # Boolean features
        boolean_features = [6, 7, 9, 10, 11, 13, 14, 16, 18, 19, 20, 21, 22]
        for idx in boolean_features:
            X[:, idx] = np.random.choice([0, 1], size=n_samples, p=[0.7, 0.3])

        # Domain age (0-3650 days, with more weight on newer domains)
        X[:, 17] = np.random.exponential(scale=365, size=n_samples)
        X[:, 17] = np.clip(X[:, 17], 0, 3650)

        # Scale the features
        X = self.scaler.fit_transform(X)

        # Generate synthetic labels (70% legitimate, 30% phishing)
        y = np.random.choice([0, 1], size=n_samples, p=[0.7, 0.3])

        # Train the model
        self.model.fit(X, y)

        # Save the model and scaler
        os.makedirs('models', exist_ok=True)
        with open('models/phishing_model.pkl', 'wb') as f:
            pickle.dump((self.model, self.scaler), f)

    def predict(self, features):
        """Predict whether a URL is phishing based on its features."""
        # Scale features
        features_scaled = self.scaler.transform([features])

        # Get probability scores
        prob = self.model.predict_proba(features_scaled)[0]
        prediction = self.model.predict(features_scaled)[0]

        # Get feature importance
        feature_importance = self.model.feature_importances_

        # Get prediction confidence and risk level
        confidence = float(max(prob))
        risk_level = self._calculate_risk_level(confidence, prediction)

        # Get top contributing features
        top_features = self._get_top_contributing_features(features, feature_importance)

        return {
            'is_phishing': bool(prediction),
            'confidence': confidence,
            'risk_level': risk_level,
            'probabilities': {
                'legitimate': float(prob[0]),
                'phishing': float(prob[1])
            },
            'feature_importance': feature_importance.tolist(),
            'top_contributing_features': top_features,
            'timestamp': datetime.now().isoformat()
        }

    def _calculate_risk_level(self, confidence, prediction):
        """Calculate risk level based on prediction and confidence."""
        if prediction == 0:  # Legitimate
            if confidence >= 0.9:
                return "Very Low Risk"
            elif confidence >= 0.7:
                return "Low Risk"
            else:
                return "Moderate Risk"
        else:  # Phishing
            if confidence >= 0.9:
                return "Critical Risk"
            elif confidence >= 0.7:
                return "High Risk"
            else:
                return "Moderate Risk"

    def _get_top_contributing_features(self, features, importance, top_n=5):
        """Get top contributing features to the prediction."""
        feature_names = [
            'URL Length', 'Domain Length', 'Path Length', 'Number of Digits',
            'Special Characters', 'Suspicious Words', 'HTTPS', 'IP Address',
            'Subdomain Count', '@Symbol', 'Double Slash', 'Hexadecimal',
            'Path Segments', 'Port Present', 'Fragment Present', 'Query Parameters',
            'Suspicious TLD', 'Domain Age', 'SSL Certificate', 'Suspicious Redirects',
            'Multiple Subdomains', 'Data URI', 'Unusual Characters'
        ]

        # Combine features with their importance
        feature_importance = list(zip(feature_names, features, importance))

        # Sort by absolute importance
        feature_importance.sort(key=lambda x: abs(x[2]), reverse=True)

        # Return top N features with their values and importance
        return [{
            'name': name,
            'value': float(value),
            'importance': float(imp)
        } for name, value, imp in feature_importance[:top_n]]