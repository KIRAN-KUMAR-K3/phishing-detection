"""
Comprehensive threat analysis combining ML and VirusTotal results.
"""
from services.virustotal_service import VirusTotalService
from utils.feature_extractor import URLFeatureExtractor
from utils.model_handler import PhishingDetectionModel
from datetime import datetime
from typing import Dict, Tuple, List

class ThreatAnalyzer:
    def __init__(self, virustotal_api_key: str):
        self.feature_extractor = URLFeatureExtractor()
        self.model = PhishingDetectionModel()
        self.vt_service = VirusTotalService(virustotal_api_key)

    def analyze_url(self, url: str) -> Dict:
        """
        Perform comprehensive URL analysis using both ML model and VirusTotal.
        """
        # Get ML model prediction
        feature_vector, feature_dict = self.feature_extractor.extract_features(url)
        ml_result = self.model.predict(feature_vector)

        # Get VirusTotal analysis
        vt_result = self.vt_service.analyze_url(url)

        # Combine results
        combined_risk = self._calculate_combined_risk(ml_result, vt_result)
        
        # Add risk factors based on detection reasons
        risk_factors = []
        
        # Add VT detection as a risk factor
        if vt_result['success'] and vt_result['detections'] > 0:
            risk_factors.append(f"Detected by {vt_result['detections']} security vendors")
            for category in vt_result['categories'][:3]:  # Limit to first 3 categories
                risk_factors.append(f"Classified as: {category}")
        
        # Add ML model risk factors if confidence is high
        if ml_result['confidence'] > 0.6:
            risk_factors.append(f"Machine learning model detected suspicious patterns with {int(ml_result['confidence']*100)}% confidence")
            
            # Add specific feature-based risk factors
            if feature_dict.get('suspicious_words_count', 0) > 2:
                risk_factors.append(f"Contains {feature_dict.get('suspicious_words_count')} suspicious keywords")
            
            if feature_dict.get('url_length', 0) > 100:
                risk_factors.append("Unusually long URL")
                
            if feature_dict.get('has_ip_address', False):
                risk_factors.append("Uses IP address instead of domain name")
                
            if feature_dict.get('has_suspicious_tld', False):
                risk_factors.append("Uses uncommon or suspicious top-level domain")
        
        # Add the risk factors to the combined risk assessment
        combined_risk['risk_factors'] = risk_factors
        
        return {
            'timestamp': datetime.now().isoformat(),
            'url': url,
            'risk_assessment': combined_risk,
            'ml_analysis': ml_result,
            'virustotal_analysis': vt_result,
            'features': feature_dict
        }

    def _calculate_combined_risk(self, ml_result: Dict, vt_result: Dict) -> Dict:
        """
        Calculate combined risk score from ML and VirusTotal results.
        """
        ml_confidence = ml_result['confidence']
        vt_detection_rate = (
            vt_result['detections'] / vt_result['total_engines']
            if vt_result['success'] and vt_result['total_engines'] > 0
            else 0
        )

        # Weight the scores (ML: 60%, VT: 40%)
        combined_score = (ml_confidence * 0.6) + (vt_detection_rate * 0.4)

        risk_levels = {
            (0.9, 1.0): "Critical Risk",
            (0.7, 0.9): "High Risk",
            (0.4, 0.7): "Moderate Risk",
            (0.2, 0.4): "Low Risk",
            (0.0, 0.2): "Very Low Risk"
        }

        for (min_score, max_score), level in risk_levels.items():
            if min_score <= combined_score <= max_score:
                risk_level = level
                break
        else:
            risk_level = "Unknown Risk"

        # Consider a URL malicious if either:
        # 1. The combined score is above 0.5 OR
        # 2. VirusTotal has at least 1 detection
        is_malicious = combined_score > 0.5 or (vt_result['success'] and vt_result['detections'] > 0)
        
        return {
            'combined_score': combined_score,
            'risk_level': risk_level,
            'ml_confidence': ml_confidence,
            'vt_detection_rate': vt_detection_rate,
            'is_malicious': is_malicious
        }
