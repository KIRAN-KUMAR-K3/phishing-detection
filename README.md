# Phishing Detection and Threat Intelligence System

## 📌 Project Overview
The **Phishing Detection and Threat Intelligence System** is an AI-powered application designed to analyze and detect malicious URLs in real-time. By leveraging machine learning techniques and integrating with VirusTotal, this system helps prevent cyber threats by identifying phishing links and harmful websites.

## 🚀 Features
- **AI-Based Phishing Detection**: Uses machine learning models to classify URLs as safe or malicious.
- **VirusTotal Integration**: Fetches threat intelligence data to enhance detection accuracy.
- **Real-Time Analysis**: Processes URLs instantly to determine security risks.
- **User-Friendly Interface**: Built with Streamlit for an interactive and easy-to-use web application.
- **Logging & Monitoring**: Keeps track of scanned URLs and results for security auditing.

## 🏗️ Project Structure
```
phishing-detection/
│── .streamlit/          # Streamlit configuration files
│── attached_assets/     # UI assets and icons
│── config/              # Configuration files
│── logs/                # Log files for monitoring
│── models/              # Pre-trained ML models
│── services/            # Backend services for URL analysis
│── styles/              # UI styling files
│── utils/               # Utility functions
│── app.py               # Main Streamlit application
│── requirements.txt     # Required dependencies
│── README.md            # Project documentation
│── .env                 # Environment variables
```

## 🛠️ Installation & Setup
### 1️⃣ Prerequisites
Ensure you have Python installed. You can check by running:
```bash
python --version
```

### 2️⃣ Clone the Repository
```bash
git clone https://github.com/KIRAN-KUMAR-K3/phishing-detection.git
cd phishing-detection
```

### 3️⃣ Create a Virtual Environment
```bash
python -m venv venv
source venv/bin/activate  # On macOS/Linux
venv\Scripts\activate  # On Windows
```

### 4️⃣ Install Dependencies
```bash
pip install -r requirements.txt
```

### 5️⃣ Set Up Environment Variables
Create a `.env` file and configure your VirusTotal API key:
```env
VIRUSTOTAL_API_KEY=your_api_key_here
```

### 6️⃣ Run the Application
```bash
streamlit run app.py
```

## 🎯 Usage
1. Open the web application in your browser.
2. Enter a URL in the input field.
3. Click the **Analyze** button.
4. The system will classify the URL and display the results.

## 🛡️ Security Considerations
- Ensure your API keys are stored securely in the `.env` file.
- Regularly update the machine learning model for improved accuracy.
- Use logging for monitoring phishing attempts.

## 🤝 Contributing
We welcome contributions! Feel free to submit issues or pull requests to improve the project.

## 📜 License
This project is licensed under the **MIT License**.

## 📧 Contact
For any queries, reach out to:
- **Author**: Kiran Kumar K
- **Email**: 18kirankumar.k03@gmail.com
- **GitHub**: [KIRAN-KUMAR-K3](https://github.com/KIRAN-KUMAR-K3)

---
**💡 Stay Safe Online! Protect Yourself from Phishing Attacks.** 🔒
