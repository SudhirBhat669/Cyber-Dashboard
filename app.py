from flask import Flask, render_template, request, send_file
import pandas as pd
import sqlite3, smtplib, io
import matplotlib.pyplot as plt
import seaborn as sns
import base64
from email.message import EmailMessage
import joblib

app = Flask(__name__)
DB_PATH = 'database/threat_logs.db'
model = joblib.load('model/model.pkl')
data = pd.read_csv('dataset/preprocessed_data.csv')

def send_email_alert(subject, body):
    msg = EmailMessage()
    msg.set_content(body)
    msg["Subject"] = subject
    msg["From"] = "sudhirbhat.669@gmail.com"
    msg["To"] = "sudhirbhat.669@gmail.com"
    with smtplib.SMTP("smtp.gmail.com", 587) as server:
        server.starttls()
        server.login("sudhirbhat.669@gmail.com", "gsagwskxfemyimyi")
        server.send_message(msg)

@app.route('/', methods=['GET', 'POST'])
def index():
    country = request.form.get("country")
    anomaly = request.form.get("anomaly")
    df = data.copy()
    if country and country != "All":
        df = df[df['src_ip_country_code'] == country]
    if anomaly and anomaly != "All":
        df = df[df['anomaly'] == anomaly]

    if df[df["anomaly"] == "Suspicious"].shape[0] > 3:
        send_email_alert("Suspicious Activity Alert", "More than 3 suspicious logs detected!")

    # Graph
    fig, ax = plt.subplots(figsize=(8, 4))
    if not df.empty:
        df = df.sort_values("creation_time")
        sns.lineplot(data=df.head(50), x="creation_time", y="bytes_in", label="Bytes In", ax=ax)
        sns.lineplot(data=df.head(50), x="creation_time", y="bytes_out", label="Bytes Out", ax=ax)
    plt.xticks(rotation=45)
    plt.tight_layout()
    img = io.BytesIO()
    plt.savefig(img, format='png')
    img.seek(0)
    plot_url = base64.b64encode(img.getvalue()).decode()

    return render_template("dashboard.html", tables=[df.head(10).to_html(classes='data')],
                           countries=["All"] + sorted(data['src_ip_country_code'].unique()),
                           anomalies=["All", "Normal", "Suspicious"],
                           selected_country=country, selected_anomaly=anomaly, plot_url=plot_url)

if __name__ == '__main__':
    app.run(debug=True)
