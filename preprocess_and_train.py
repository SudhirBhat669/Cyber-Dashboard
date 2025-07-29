import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler, OneHotEncoder
from packaging import version
import sklearn
import joblib
import os
import sqlite3
import warnings
warnings.filterwarnings("ignore")

# Load dataset
df = pd.read_csv("CloudWatch_Traffic_Web_Attack.csv")

# Convert timestamps
df['creation_time'] = pd.to_datetime(df['creation_time'])
df['end_time'] = pd.to_datetime(df['end_time'])
df['time'] = pd.to_datetime(df['time'])

# Feature engineering
df['duration_seconds'] = (df['end_time'] - df['creation_time']).dt.total_seconds()

# Scale numeric features
scaler = StandardScaler()
df[['bytes_in_scaled', 'bytes_out_scaled', 'duration_scaled']] = scaler.fit_transform(
    df[['bytes_in', 'bytes_out', 'duration_seconds']]
)

# One-hot encoding country codes (version-compatible)
if version.parse(sklearn.__version__) >= version.parse("1.2"):
    encoder = OneHotEncoder(sparse_output=False)
else:
    encoder = OneHotEncoder(sparse=False)

encoded = encoder.fit_transform(df[['src_ip_country_code']])
encoded_df = pd.DataFrame(encoded, columns=encoder.get_feature_names_out(['src_ip_country_code']))
df = pd.concat([df.reset_index(drop=True), encoded_df], axis=1)

# Anomaly detection using Isolation Forest
features = df[['bytes_in', 'bytes_out', 'duration_seconds']]
model = IsolationForest(contamination=0.05, random_state=42)
df['anomaly'] = model.fit_predict(features)
df['anomaly'] = df['anomaly'].apply(lambda x: 'Suspicious' if x == -1 else 'Normal')

# Save model and dataset
os.makedirs("model", exist_ok=True)
os.makedirs("dataset", exist_ok=True)
joblib.dump(model, "model/model.pkl")
df.to_csv("dataset/preprocessed_data.csv", index=False)

# Store in SQLite database
os.makedirs("database", exist_ok=True)
conn = sqlite3.connect("database/threat_logs.db")
cursor = conn.cursor()

cursor.execute('''CREATE TABLE IF NOT EXISTS web_traffic_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    src_ip TEXT,
    dst_ip TEXT,
    src_country TEXT,
    dst_port INTEGER,
    bytes_in INTEGER,
    bytes_out INTEGER,
    anomaly TEXT,
    creation_time TEXT
)''')

# Insert first 50 rows into database with proper type conversion
for _, row in df[['src_ip','dst_ip','src_ip_country_code','dst_port','bytes_in','bytes_out','anomaly','creation_time']].head(50).iterrows():
    cursor.execute("""
        INSERT INTO web_traffic_logs (
            src_ip, dst_ip, src_country, dst_port,
            bytes_in, bytes_out, anomaly, creation_time
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
        (row['src_ip'], row['dst_ip'], row['src_ip_country_code'], row['dst_port'],
         row['bytes_in'], row['bytes_out'], row['anomaly'], str(row['creation_time']))
    )

conn.commit()
conn.close()

print("✅ Preprocessing complete. Model and data saved.")
