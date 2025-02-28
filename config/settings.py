"""
Configuration settings for the Phishing Detection System.
"""
import os
from dataclasses import dataclass

@dataclass
class APIConfig:
    virustotal_api_key: str = os.getenv('VIRUSTOTAL_API_KEY', '')

@dataclass
class AppConfig:
    title: str = "Professional Phishing Detection System"
    description: str = "Advanced threat detection and URL analysis system"
    version: str = "2.0.0"
    theme_config = {
        "primaryColor": "#FF4B4B",
        "backgroundColor": "#0E1117",
        "secondaryBackgroundColor": "#262730",
        "textColor": "#FAFAFA",
    }

config = AppConfig()
api_config = APIConfig()
