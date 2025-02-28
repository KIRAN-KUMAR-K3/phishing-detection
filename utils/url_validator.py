import re
import requests
from urllib.parse import urlparse

class URLValidator:
    @staticmethod
    def is_valid_url(url):
        """Check if the URL is valid."""
        # Add http:// prefix if not present
        if not url.startswith('http://') and not url.startswith('https://'):
            url = 'http://' + url
            
        try:
            result = urlparse(url)
            return all([result.scheme, result.netloc])
        except:
            return False
    
    @staticmethod
    def check_url_accessibility(url):
        """Check if the URL is accessible."""
        # Add http:// prefix if not present
        if not url.startswith('http://') and not url.startswith('https://'):
            url = 'http://' + url
            
        try:
            response = requests.head(url, timeout=5, allow_redirects=True)
            return 200 <= response.status_code < 400
        except:
            return False
