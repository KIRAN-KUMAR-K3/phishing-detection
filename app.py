import streamlit as st
import pandas as pd
import plotly.graph_objects as go
import plotly.express as px
from datetime import datetime
import json
import os
import time
import base64
import io
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

from utils.threat_analyzer import ThreatAnalyzer
from utils.url_validator import URLValidator
from config.settings import config

# Page configuration
st.set_page_config(
    page_title=config.title,
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
    menu_items={
        'Get Help': 'https://github.com/KIRAN-KUMAR-K3/phishing-detection',
        'Report a bug': "https://github.com/KIRAN-KUMAR-K3/phishing-detection/issues",
        'About': "# Professional Phishing Detection System\nVersion " + config.version
    }
)

# Helper functions
def update_threat_stats(result):
    """Update threat statistics."""
    st.session_state.threat_stats['total_scans'] += 1
    risk_assessment = result.get('risk_assessment', {})

    if risk_assessment.get('is_malicious', False):
        st.session_state.threat_stats['phishing_detected'] += 1
        if risk_assessment.get('combined_score', 0) > 0.8:
            st.session_state.threat_stats['high_risk_threats'] += 1
    else:
        st.session_state.threat_stats['legitimate_sites'] += 1

    vt_analysis = result.get('virustotal_analysis', {})
    if vt_analysis.get('success', False):
        st.session_state.threat_stats['vt_detections'] += vt_analysis.get('detections', 0)

def export_results_csv():
    """Export analysis history to CSV."""
    if not st.session_state.analysis_history:
        return None
    df = pd.DataFrame(st.session_state.analysis_history)
    csv = df.to_csv(index=False)
    return f'data:file/csv;base64,{base64.b64encode(csv.encode()).decode()}'

def export_results_json():
    """Export analysis history to JSON."""
    if not st.session_state.analysis_history:
        return None
    json_str = json.dumps(st.session_state.analysis_history, indent=2)
    return f'data:file/json;base64,{base64.b64encode(json_str.encode()).decode()}'

# Initialize session state
if 'analysis_history' not in st.session_state:
    st.session_state.analysis_history = []
if 'threat_stats' not in st.session_state:
    st.session_state.threat_stats = {
        'total_scans': 0,
        'phishing_detected': 0,
        'legitimate_sites': 0,
        'high_risk_threats': 0,
        'vt_detections': 0
    }

# Load custom CSS
with open('styles/custom.css') as f:
    st.markdown(f'<style>{f.read()}</style>', unsafe_allow_html=True)

# Initialize components
@st.cache_resource
def initialize_analyzer():
    api_key = os.getenv('VIRUSTOTAL_API_KEY')
    if not api_key:
        st.error("VirusTotal API key not found. Some features may be limited.")
    return ThreatAnalyzer(api_key)

analyzer = initialize_analyzer()
url_validator = URLValidator()

# Sidebar Navigation
with st.sidebar:
    st.image("https://img.icons8.com/color/96/000000/shield.png", width=100)
    st.title("Navigation")

    # Custom navigation style
    st.markdown("""
        <style>
        div.row-widget.stRadio > div {
            flex-direction: column;
            gap: 1rem;
        }
        div.row-widget.stRadio > div[role="radiogroup"] > label {
            padding: 1rem;
            background-color: rgba(255, 255, 255, 0.05);
            border-radius: 0.5rem;
            cursor: pointer;
            transition: all 0.3s ease;
        }
        div.row-widget.stRadio > div[role="radiogroup"] > label:hover {
            background-color: rgba(255, 255, 255, 0.1);
            transform: translateX(5px);
        }
        </style>
    """, unsafe_allow_html=True)

    selected_page = st.radio(
        "Select Page",
        ["🎯 Dashboard", "🔍 URL Analysis", "📊 Threat Intelligence", "📜 Analysis History", "ℹ️ About"],
        key="navigation"
    )

# Main content area
if "Dashboard" in selected_page:
    st.title("🎯 Advanced Threat Intelligence Dashboard")

    # Dashboard metrics
    col1, col2, col3, col4 = st.columns(4)
    with col1:
        st.metric(
            "Total Scans",
            st.session_state.threat_stats['total_scans'],
            help="Total number of URLs analyzed"
        )
    with col2:
        st.metric(
            "Threats Detected",
            st.session_state.threat_stats['phishing_detected'],
            delta=f"{st.session_state.threat_stats['high_risk_threats']} High Risk",
            delta_color="inverse"
        )
    with col3:
        st.metric(
            "Safe URLs",
            st.session_state.threat_stats['legitimate_sites'],
            help="URLs verified as legitimate"
        )
    with col4:
        st.metric(
            "VirusTotal Detections",
            st.session_state.threat_stats['vt_detections'],
            help="Cumulative detections from VirusTotal"
        )

    # Threat Intelligence Overview
    st.subheader("🔍 Threat Intelligence Overview")
    if st.session_state.analysis_history:
        try:
            # Create threat detection timeline
            df = pd.DataFrame(st.session_state.analysis_history)
            threat_scores = []
            timestamps = []

            for entry in st.session_state.analysis_history:
                risk_assessment = entry.get('risk_assessment', {})
                timestamps.append(entry.get('timestamp', ''))
                threat_scores.append(risk_assessment.get('combined_score', 0))

            fig = go.Figure()
            fig.add_trace(go.Scatter(
                x=pd.to_datetime(timestamps),
                y=threat_scores,
                name='Threat Score',
                mode='lines+markers',
                line=dict(color='#FF4B4B')
            ))

            fig.update_layout(
                title="Threat Detection Timeline",
                xaxis_title="Time",
                yaxis_title="Threat Score",
                plot_bgcolor='rgba(0,0,0,0)',
                paper_bgcolor='rgba(0,0,0,0)',
                font_color='#FAFAFA',
                showlegend=True
            )
            st.plotly_chart(fig, use_container_width=True)

        except Exception as e:
            st.warning("Error displaying threat timeline. Some data may be missing.")

elif "URL Analysis" in selected_page:
    st.title("🔍 Advanced URL Analysis")

    st.markdown("""
        <div class="main-description">
            Our AI-powered phishing detection combines:
            - 🤖 Machine Learning Analysis
            - 🌐 VirusTotal Integration
            - 🔒 SSL/Security Verification
            - 🚨 Real-time Threat Detection
        </div>
    """, unsafe_allow_html=True)

    # URL input
    url = st.text_input(
        "Enter URL to analyze:",
        placeholder="https://example.com",
        help="Enter the complete URL including http:// or https://"
    )

    if st.button("Analyze URL", type="primary"):
        if not url:
            st.warning("Please enter a URL to analyze")
        else:
            with st.spinner("🔍 Performing comprehensive security analysis..."):
                if not url_validator.is_valid_url(url):
                    st.error("⚠️ Invalid URL format. Please enter a valid URL")
                else:
                    try:
                        # Perform analysis
                        result = analyzer.analyze_url(url)

                        # Create analysis tabs
                        tabs = st.tabs(["Results", "Technical Details", "Security Score", "Threat Intel"])

                        with tabs[0]:
                            col1, col2 = st.columns([2, 1])
                            with col1:
                                if result['risk_assessment']['is_malicious']:
                                    st.error(f"🚨 {result['risk_assessment']['risk_level']}")
                                    st.markdown("### Key Risk Indicators:")
                                    for indicator in result['risk_assessment']['risk_factors']:
                                        st.warning(f"⚠️ {indicator}")
                                else:
                                    st.success("✅ URL appears to be safe")

                            with col2:
                                # Risk score gauge
                                fig = go.Figure(go.Indicator(
                                    mode="gauge+number",
                                    value=result['risk_assessment']['combined_score'] * 100,
                                    title={'text': "Risk Score"},
                                    gauge={'axis': {'range': [0, 100]}}
                                ))
                                st.plotly_chart(fig, use_container_width=True)

                        with tabs[1]:
                            st.subheader("Technical Analysis")
                            st.json(result['features'])

                        with tabs[2]:
                            st.subheader("Security Metrics")
                            metrics = st.columns(3)
                            with metrics[0]:
                                st.metric("HTTPS Security",
                                    "Secure" if result['features']['is_https'] else "Not Secure")
                            with metrics[1]:
                                st.metric("SSL Certificate",
                                    "Valid" if result['features']['has_ssl_cert'] else "Invalid")
                            with metrics[2]:
                                st.metric("Domain Age",
                                    f"{result['features']['domain_age_days']} days")

                        with tabs[3]:
                            st.subheader("VirusTotal Results")
                            if result['virustotal_analysis']['success']:
                                st.metric("Detection Rate",
                                    f"{result['virustotal_analysis']['detections']}/{result['virustotal_analysis']['total_engines']}")
                                if result['virustotal_analysis']['categories']:
                                    st.markdown("### Threat Categories")
                                    for category in result['virustotal_analysis']['categories']:
                                        st.warning(f"- {category}")
                            else:
                                st.info("VirusTotal analysis not available")

                        # Update stats and history
                        update_threat_stats(result)
                        st.session_state.analysis_history.append(result)

                    except Exception as e:
                        st.error(f"Error analyzing URL: {str(e)}")

elif "Threat Intelligence" in selected_page:
    st.title("📊 Threat Intelligence Center")

    if st.session_state.analysis_history:
        try:
            # Process data for visualization
            risk_levels = []
            for entry in st.session_state.analysis_history:
                risk_assessment = entry.get('risk_assessment', {})
                risk_levels.append(risk_assessment.get('risk_level', 'Unknown'))

            risk_counts = pd.Series(risk_levels).value_counts()

            # Create risk distribution visualization
            fig = go.Figure()
            
            # Create color map for risk levels
            colors = []
            color_map = {
                'Very Low Risk': 'green',
                'Low Risk': 'lightgreen',
                'Moderate Risk': 'yellow',
                'High Risk': 'orange',
                'Critical Risk': 'red',
                'Unknown': 'gray'
            }
            
            # Apply colors based on risk level
            for risk in risk_counts.index:
                colors.append(color_map.get(risk, 'gray'))
                
            fig.add_trace(go.Bar(
                x=risk_counts.index,
                y=risk_counts.values,
                marker_color=colors
            ))

            fig.update_layout(
                title="Risk Level Distribution",
                xaxis_title="Risk Level",
                yaxis_title="Number of URLs",
                plot_bgcolor='rgba(0,0,0,0)',
                paper_bgcolor='rgba(0,0,0,0)',
                font_color='#FAFAFA'
            )

            st.plotly_chart(fig, use_container_width=True)

            # Summary statistics
            st.subheader("Analysis Summary")
            col1, col2, col3 = st.columns(3)

            with col1:
                st.metric(
                    "Total Scans",
                    len(st.session_state.analysis_history),
                    help="Total number of URLs analyzed"
                )

            with col2:
                high_risk_count = sum(1 for entry in st.session_state.analysis_history
                                    if entry.get('risk_assessment', {}).get('is_malicious', False))
                st.metric(
                    "High Risk URLs",
                    high_risk_count,
                    help="URLs identified as potentially malicious"
                )

            with col3:
                vt_detections = sum(entry.get('virustotal_analysis', {}).get('detections', 0)
                                  for entry in st.session_state.analysis_history)
                st.metric(
                    "VirusTotal Detections",
                    vt_detections,
                    help="Total detections from VirusTotal"
                )

            # Export capabilities
            st.subheader("📤 Export Analysis Data")
            col1, col2 = st.columns(2)
            with col1:
                csv_data = export_results_csv()
                if csv_data:
                    st.markdown(
                        f'<a href="{csv_data}" download="threat_analysis.csv" '
                        'class="streamlit-button">Export as CSV</a>',
                        unsafe_allow_html=True
                    )
            with col2:
                json_data = export_results_json()
                if json_data:
                    st.markdown(
                        f'<a href="{json_data}" download="threat_analysis.json" '
                        'class="streamlit-button">Export as JSON</a>',
                        unsafe_allow_html=True
                    )

        except Exception as e:
            st.error(f"Error processing threat intelligence data: {str(e)}")
            st.info("Try analyzing more URLs to generate comprehensive threat intelligence.")
    else:
        st.info("Start analyzing URLs to view threat intelligence insights")

elif "Analysis History" in selected_page:
    st.title("📜 Analysis History")
    if st.session_state.analysis_history:
        for entry in reversed(st.session_state.analysis_history):
            with st.expander(f"Analysis of {entry['url']} - {entry['timestamp']}"):
                col1, col2 = st.columns(2)
                with col1:
                    st.markdown("### Analysis Results")
                    risk = entry['risk_assessment']
                    st.markdown(f"**Risk Level**: {risk['risk_level']}")
                    st.markdown(f"**ML Confidence**: {risk['ml_confidence']*100:.1f}%")
                    st.markdown(f"**VT Detection Rate**: {risk['vt_detection_rate']*100:.1f}%")
                with col2:
                    st.markdown("### Security Metrics")
                    features = entry['features']
                    st.markdown(f"- **HTTPS**: {'Yes' if features['is_https'] else 'No'}")
                    st.markdown(f"- **Domain Age**: {features['domain_age_days']} days")
                    st.markdown(f"- **SSL Certificate**: {'Valid' if features['has_ssl_cert'] else 'Invalid'}")
    else:
        st.info("No analysis history available. Start by analyzing some URLs!")

else:  # About page
    st.title("ℹ️ About This System")
    st.markdown("""
    ### AI-Powered Phishing Detection System

    This advanced cybersecurity tool combines machine learning and real-time threat intelligence
    to protect against phishing attacks and cyber threats.

    #### Key Features:
    - 🤖 AI-based phishing detection using ML models
    - 🔍 Advanced URL & domain analysis
    - 🔐 SSL/Security verification
    - 🌐 Real-time threat intelligence
    - 📊 Comprehensive security dashboard
    - 🔄 VirusTotal Integration
    - 📈 Historical Analysis
    - 📋 Detailed Reporting

    Version: {.Version: 1.0.0}
    """)

# Force dark theme
st.markdown("""
    <script>
        document.querySelector('body').style.backgroundColor = '#0E1117';
        document.querySelector('.main').style.backgroundColor = '#0E1117';
    </script>
""", unsafe_allow_html=True)