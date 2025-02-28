import re
from urllib.parse import urlparse
import numpy as np
import ipaddress
import tld
from datetime import datetime
import whois as whois_module
import dns.resolver
import requests

class URLFeatureExtractor:
    def __init__(self):
        self.suspicious_words = [
            'login', 'signin', 'verify', 'secure', 'account', 'update', 'confirm',
            'banking', 'payment', 'authenticate', 'verification', 'password',
            'credential', 'wallet', 'security', 'unauthorize', 'paypal', 'bitcoin',
            'recover', 'unlock', 'validate', 'maintenance', 'support', 'helpdesk'
        ]

        self.legitimate_tlds = {'.com', '.org', '.net', '.edu', '.gov', '.mil'}

    def extract_features(self, url):
        """Extract comprehensive features from URL for phishing detection."""
        features = {}
        parsed = urlparse(url)
        domain = parsed.netloc

        # Basic URL characteristics
        features.update(self._extract_basic_features(url, parsed))

        # Domain-specific features
        features.update(self._extract_domain_features(domain))

        # Security features
        features.update(self._extract_security_features(url, domain))

        # Content-based features
        features.update(self._extract_content_features(url))

        # Convert features to vector
        feature_vector = self._create_feature_vector(features)

        return feature_vector, features

    def _extract_basic_features(self, url, parsed):
        """Extract basic URL characteristics."""
        return {
            'url_length': len(url),
            'domain_length': len(parsed.netloc),
            'path_length': len(parsed.path),
            'num_digits': sum(c.isdigit() for c in url),
            'num_special_chars': len(re.findall(r'[^a-zA-Z0-9.]', url)),
            'num_segments': len(parsed.path.split('/')),
            'has_port': bool(parsed.port),
            'has_fragment': bool(parsed.fragment),
            'num_queries': len(parsed.query.split('&')) if parsed.query else 0
        }

    def _extract_domain_features(self, domain):
        """Extract domain-specific features."""
        features = {
            'has_ip_address': self._is_ip_address(domain),
            'subdomain_count': domain.count('.') - 1 if domain else 0,
            'is_https': False,  # Will be set in security features
            'has_suspicious_tld': not any(domain.endswith(tld) for tld in self.legitimate_tlds),
            'domain_age_days': 0  # Default value
        }

        # Try to get domain age
        try:
            w = whois_module.query(domain)
            if w and hasattr(w, 'creation_date'):
                creation_date = w.creation_date[0] if isinstance(w.creation_date, list) else w.creation_date
                if isinstance(creation_date, datetime):
                    age = (datetime.now() - creation_date).days
                    features['domain_age_days'] = max(0, age)  # Ensure non-negative age
                else:
                    features['domain_age_days'] = -1  # Invalid date format
            else:
                features['domain_age_days'] = -1  # No creation date available
        except Exception as e:
            print(f"Error getting domain age for {domain}: {str(e)}")
            features['domain_age_days'] = -1  # Error in whois lookup

        return features

    def _extract_security_features(self, url, domain):
        """Extract security-related features."""
        features = {
            'is_https': url.startswith('https://'),
            'has_ssl_cert': False,
            'has_suspicious_redirects': False,
            'has_multiple_subdomains': domain.count('.') > 2
        }

        # Check SSL certificate
        if features['is_https']:
            try:
                requests.get(url, verify=True, timeout=5)
                features['has_ssl_cert'] = True
            except:
                pass

        return features

    def _extract_content_features(self, url):
        """Extract content-based features."""
        return {
            'suspicious_words': sum(1 for word in self.suspicious_words if word in url.lower()),
            'has_at_symbol': int('@' in url),
            'has_double_slash': int('//' in urlparse(url).path),
            'has_hexadecimal': int(bool(re.search(r'%[0-9a-fA-F]{2}', url))),
            'has_data_uri': url.startswith('data:'),
            'has_unusual_chars': bool(re.search(r'[^a-zA-Z0-9-._~:/?#\[\]@!$&\'()*+,;=]', url))
        }

    def _is_ip_address(self, domain):
        """Check if the domain is an IP address."""
        try:
            domain = domain.split(':')[0]
            ipaddress.ip_address(domain)
            return 1
        except ValueError:
            return 0

    def _create_feature_vector(self, features):
        """Create a numpy array of features in a fixed order."""
        feature_list = [
            features['url_length'],
            features['domain_length'],
            features['path_length'],
            features['num_digits'],
            features['num_special_chars'],
            features['suspicious_words'],
            features['is_https'],
            features['has_ip_address'],
            features['subdomain_count'],
            features['has_at_symbol'],
            features['has_double_slash'],
            features['has_hexadecimal'],
            features['num_segments'],
            features['has_port'],
            features['has_fragment'],
            features['num_queries'],
            features['has_suspicious_tld'],
            features['domain_age_days'],
            features['has_ssl_cert'],
            features['has_suspicious_redirects'],
            features['has_multiple_subdomains'],
            features['has_data_uri'],
            features['has_unusual_chars']
        ]
        return np.array(feature_list)