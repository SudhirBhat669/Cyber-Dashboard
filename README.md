# 🚨 Cybersecurity: Suspicious Web Threat Interactions
A real-time Machine Learning-powered Flask dashboard that analyzes web traffic logs to detect **suspicious behaviors** using **anomaly detection**, visualizes patterns with graphs, and triggers email alerts on abnormal activity.



## 📌 Project Objective
To detect and analyze patterns in web interactions for identifying potentially harmful or malicious activities using:
- Machine Learning (Isolation Forest)
- Real-time web traffic visualization
- Email alerts for suspicious activity
- SQLite for backend log storage
- A live interactive dashboard with filters

## 📊 Features
- ✅ Preprocess & label suspicious activity in CSV web traffic logs
- ✅ Train an Isolation Forest anomaly detection model
- ✅ Visualize incoming/outgoing bytes over time (line graph)
- ✅ Filter logs by country and anomaly status on the dashboard
- ✅ Store logs in a local SQLite database
- ✅ Automatically email alert when more than 3 anomalies are detected
- ✅ Render/Heroku deployment-ready

## 🧰 Tech Stack

| Layer          | Tools Used                                      |
|----------------|-------------------------------------------------|
| Language       | Python                                          |
| Backend        | Flask                                           |
| ML Model       | Isolation Forest (Scikit-learn)                 |
| Database       | SQLite3                                         |
| Frontend       | Jinja2 (HTML), CSS, Matplotlib, Seaborn         |
| Alerts         | smtplib (email.message)                         |
| Deployment     | Render / GitHub Pages                           |

## 📂 Folder Structure
Cybersecurity_Dashboard/
├── app.py # Flask dashboard app
├── preprocess_and_train.py # Preprocessing + ML model
├── model/
│ └── model.pkl # Saved Isolation Forest model
├── dataset/
│ └── preprocessed_data.csv # Cleaned traffic data
├── database/
│ └── threat_logs.db # SQLite log storage
├── templates/
│ └── dashboard.html # Jinja2 HTML UI
├── static/
│ └── style.css # Custom dashboard styles
├── .env # SMTP & Render secrets (optional)
├── requirements.txt # All required Python packages
└── README.md

## 🧪 Local Setup Instructions
### 1. Clone the Repo
git clone https://github.com/your-username/Cyber-Dashboard.git
cd Cyber-Dashboard

## How to Run
1. Install requirements:
pip install -r requirements.txt

2. Create Virtual Environment (Optional)
python -m venv venv
source venv/bin/activate  # On Windows: venv\\Scripts\\activate

3. Install Requirements
bash
Copy
Edit
pip install -r requirements.txt
4. Preprocess and Train Model
python preprocess_and_train.py
5. Start Flask App
python app.py
Then open your browser and navigate to:
Open in browser: http://127.0.0.1:5000/