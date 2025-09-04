import json
import time
import numpy as np
from sklearn.ensemble import IsolationForest
from openai import OpenAI

# --- Initialize Models ---
anomaly_model = IsolationForest(n_estimators=100, contamination=0.01, random_state=42)
client = OpenAI(api_key="YOUR_API_KEY")

# --- Simulated training data (replace with real network logs) ---
X_train = np.random.normal(0, 1, (1000, 5))  # 1000 samples, 5 features
anomaly_model.fit(X_train)

# --- Streaming Function ---
def stream_events():
    while True:
        # Simulate incoming event (normally from Kafka / logs / packets)
        event = np.random.normal(0, 1, (1, 5))
        yield event
        time.sleep(1)  # mimic real-time delay

# --- Threat Detection Pipeline ---
for event in stream_events():
    score = anomaly_model.decision_function(event)
    is_anomaly = anomaly_model.predict(event)[0] == -1

    if is_anomaly:
        description = client.chat.completions.create(
            model="gpt-4.1-mini",
            messages=[
                {"role": "system", "content": "You are a cybersecurity assistant."},
                {"role": "user", "content": f"Explain this anomaly: {event.tolist()} with score {score}"}
            ]
        )
        print("⚠️ Threat Detected:", event.tolist())
        print("LLM Insight:", description.choices[0].message["content"])
    else:
        print("✅ Normal Event:", event.tolist())
