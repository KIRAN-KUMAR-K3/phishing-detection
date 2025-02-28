"""
VirusTotal API integration service for enhanced threat detection.
"""
import requests
from typing import Dict, Optional
import hashlib
import base64
import time

class VirusTotalService:
    def __init__(self, api_key: str):
        self.api_key = api_key
        self.base_url = "https://www.virustotal.com/vtapi/v2"
        self.headers = {
            "Accept": "application/json",
            "x-apikey": self.api_key
        }

    def analyze_url(self, url: str) -> Dict:
        """
        Analyze a URL using VirusTotal API.
        """
        try:
            # Submit URL for scanning
            params = {'apikey': self.api_key, 'url': url}
            scan_response = requests.post(
                f"{self.base_url}/url/scan",
                data=params
            )
            scan_response.raise_for_status()
            scan_id = scan_response.json().get('scan_id')

            # Wait briefly for analysis
            time.sleep(3)

            # Get the results
            params = {'apikey': self.api_key, 'resource': scan_id}
            report_response = requests.get(
                f"{self.base_url}/url/report",
                params=params
            )
            report_response.raise_for_status()
            
            return self._process_report(report_response.json())
        except Exception as e:
            return {
                'success': False,
                'error': str(e),
                'detections': 0,
                'total_engines': 0,
                'categories': []
            }

    def _process_report(self, report: Dict) -> Dict:
        """Process and format the VirusTotal report."""
        if not report:
            return {
                'success': False,
                'error': 'No report data available',
                'detections': 0,
                'total_engines': 0,
                'categories': []
            }

        return {
            'success': True,
            'scan_date': report.get('scan_date'),
            'detections': report.get('positives', 0),
            'total_engines': report.get('total', 0),
            'permalink': report.get('permalink', ''),
            'scans': report.get('scans', {}),
            'categories': self._extract_categories(report)
        }

    def _extract_categories(self, report: Dict) -> list:
        """Extract threat categories from the report."""
        categories = set()
        scans = report.get('scans', {})
        
        for scanner_result in scans.values():
            result = scanner_result.get('result')
            if result and result != 'clean site':
                categories.add(result)
        
        return list(categories)
