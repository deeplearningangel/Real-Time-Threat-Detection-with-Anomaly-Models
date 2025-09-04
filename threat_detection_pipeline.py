import asyncio
import json
import logging
import numpy as np
import pandas as pd
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple, Any
import pickle
import warnings
warnings.filterwarnings('ignore')

# Core ML libraries
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.model_selection import train_test_split
import tensorflow as tf
from tensorflow import keras
from tensorflow.keras import layers

# Streaming and async libraries
import asyncio
import aiohttp
import aioredis
from kafka import KafkaConsumer, KafkaProducer
import threading
from queue import Queue
import time

# LLM integration (using OpenAI as example)
import openai

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class NetworkLogFeatureExtractor:
    """Extracts features from network logs and system events"""
    
    def __init__(self):
        self.scaler = StandardScaler()
        self.label_encoders = {}
        self.is_fitted = False
    
    def extract_features(self, log_entry: Dict) -> Dict:
        """Extract numerical and categorical features from log entry"""
        features = {}
        
        # Time-based features
        timestamp = pd.to_datetime(log_entry.get('timestamp', datetime.now()))
        features['hour'] = timestamp.hour
        features['day_of_week'] = timestamp.weekday()
        features['is_weekend'] = 1 if timestamp.weekday() >= 5 else 0
        
        # Network features
        features['src_port'] = log_entry.get('src_port', 0)
        features['dst_port'] = log_entry.get('dst_port', 0)
        features['packet_size'] = log_entry.get('packet_size', 0)
        features['duration'] = log_entry.get('duration', 0)
        features['bytes_sent'] = log_entry.get('bytes_sent', 0)
        features['bytes_received'] = log_entry.get('bytes_received', 0)
        
        # Rate features (requests per minute)
        features['request_rate'] = log_entry.get('request_rate', 0)
        features['error_rate'] = log_entry.get('error_rate', 0)
        
        # Categorical features (will be encoded)
        features['protocol'] = log_entry.get('protocol', 'unknown')
        features['src_country'] = log_entry.get('src_country', 'unknown')
        features['user_agent_category'] = log_entry.get('user_agent_category', 'unknown')
        features['http_method'] = log_entry.get('http_method', 'unknown')
        features['response_code'] = log_entry.get('response_code', 200)
        
        return features
    
    def fit_transform(self, logs: List[Dict]) -> np.ndarray:
        """Fit encoders and transform training data"""
        features_list = [self.extract_features(log) for log in logs]
        df = pd.DataFrame(features_list)
        
        # Separate numerical and categorical features
        numerical_cols = ['hour', 'day_of_week', 'is_weekend', 'src_port', 'dst_port', 
                         'packet_size', 'duration', 'bytes_sent', 'bytes_received',
                         'request_rate', 'error_rate', 'response_code']
        categorical_cols = ['protocol', 'src_country', 'user_agent_category', 'http_method']
        
        # Encode categorical features
        for col in categorical_cols:
            le = LabelEncoder()
            df[col + '_encoded'] = le.fit_transform(df[col].astype(str))
            self.label_encoders[col] = le
        
        # Select final feature columns
        feature_cols = numerical_cols + [col + '_encoded' for col in categorical_cols]
        X = df[feature_cols].values
        
        # Scale features
        X_scaled = self.scaler.fit_transform(X)
        self.is_fitted = True
        
        return X_scaled
    
    def transform(self, log_entry: Dict) -> np.ndarray:
        """Transform single log entry for prediction"""
        if not self.is_fitted:
            raise ValueError("FeatureExtractor must be fitted before transform")
        
        features = self.extract_features(log_entry)
        
        # Create DataFrame for consistent processing
        df = pd.DataFrame([features])
        
        # Encode categorical features
        categorical_cols = ['protocol', 'src_country', 'user_agent_category', 'http_method']
        for col in categorical_cols:
            if col in self.label_encoders:
                # Handle unseen categories
                try:
                    df[col + '_encoded'] = self.label_encoders[col].transform(df[col].astype(str))
                except ValueError:
                    df[col + '_encoded'] = 0  # Default for unseen categories
            else:
                df[col + '_encoded'] = 0
        
        # Select features and scale
        numerical_cols = ['hour', 'day_of_week', 'is_weekend', 'src_port', 'dst_port', 
                         'packet_size', 'duration', 'bytes_sent', 'bytes_received',
                         'request_rate', 'error_rate', 'response_code']
        feature_cols = numerical_cols + [col + '_encoded' for col in categorical_cols]
        
        X = df[feature_cols].values
        X_scaled = self.scaler.transform(X)
        
        return X_scaled

class AutoencoderAnomalyDetector:
    """Deep learning autoencoder for anomaly detection"""
    
    def __init__(self, input_dim: int, encoding_dim: int = 32):
        self.input_dim = input_dim
        self.encoding_dim = encoding_dim
        self.model = None
        self.threshold = None
    
    def build_model(self):
        """Build autoencoder architecture"""
        # Encoder
        input_layer = keras.Input(shape=(self.input_dim,))
        encoder = layers.Dense(64, activation="relu")(input_layer)
        encoder = layers.Dense(self.encoding_dim, activation="relu")(encoder)
        
        # Decoder
        decoder = layers.Dense(64, activation="relu")(encoder)
        decoder = layers.Dense(self.input_dim, activation="sigmoid")(decoder)
        
        # Autoencoder model
        self.model = keras.Model(input_layer, decoder)
        self.model.compile(optimizer='adam', loss='mse')
        
        return self.model
    
    def train(self, X_train: np.ndarray, validation_split: float = 0.2, epochs: int = 50):
        """Train the autoencoder on normal data"""
        if self.model is None:
            self.build_model()
        
        history = self.model.fit(
            X_train, X_train,
            epochs=epochs,
            batch_size=32,
            shuffle=True,
            validation_split=validation_split,
            verbose=1
        )
        
        # Calculate threshold based on reconstruction error
        predictions = self.model.predict(X_train)
        mse = np.mean(np.square(X_train - predictions), axis=1)
        self.threshold = np.percentile(mse, 95)  # 95th percentile as threshold
        
        logger.info(f"Autoencoder trained. Threshold: {self.threshold:.4f}")
        return history
    
    def predict_anomaly(self, X: np.ndarray) -> Tuple[bool, float]:
        """Predict if sample is anomalous"""
        if self.model is None or self.threshold is None:
            raise ValueError("Model must be trained before prediction")
        
        reconstruction = self.model.predict(X, verbose=0)
        mse = np.mean(np.square(X - reconstruction))
        
        is_anomaly = mse > self.threshold
        anomaly_score = mse / self.threshold  # Normalized score
        
        return is_anomaly, anomaly_score

class LLMThreatAnalyzer:
    """LLM-based threat classification and explanation"""
    
    def __init__(self, api_key: str, model: str = "gpt-3.5-turbo"):
        self.client = openai.OpenAI(api_key=api_key)
        self.model = model
        
        # Threat categories
        self.threat_categories = {
            'brute_force': 'Multiple failed login attempts from same source',
            'port_scan': 'Sequential connection attempts to multiple ports',
            'ddos': 'High volume of requests from multiple sources',
            'sql_injection': 'SQL injection patterns in requests',
            'xss': 'Cross-site scripting attempt',
            'malware_c2': 'Communication with known C&C servers',
            'data_exfiltration': 'Unusual data transfer patterns',
            'privilege_escalation': 'Attempts to gain higher privileges',
            'lateral_movement': 'Suspicious internal network activity',
            'unknown_anomaly': 'Anomalous behavior with unclear classification'
        }
    
    def analyze_threat(self, log_entry: Dict, anomaly_score: float, context: Dict = None) -> Dict:
        """Analyze threat using LLM"""
        
        # Prepare context for LLM
        analysis_prompt = f"""
        You are a cybersecurity expert analyzing network logs. A machine learning model has flagged the following log entry as anomalous with a score of {anomaly_score:.3f}.

        Log Entry:
        {json.dumps(log_entry, indent=2)}

        Context (if available):
        {json.dumps(context or {}, indent=2)}

        Please analyze this log entry and provide:
        1. Threat classification from these categories: {list(self.threat_categories.keys())}
        2. Confidence level (0-100)
        3. Risk level (LOW, MEDIUM, HIGH, CRITICAL)
        4. Detailed explanation of why this is suspicious
        5. Recommended immediate actions
        6. Additional investigation steps

        Respond in JSON format with keys: classification, confidence, risk_level, explanation, immediate_actions, investigation_steps
        """
        
        try:
            response = self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": "You are a cybersecurity expert. Always respond with valid JSON."},
                    {"role": "user", "content": analysis_prompt}
                ],
                temperature=0.1,
                max_tokens=800
            )
            
            # Parse LLM response
            analysis = json.loads(response.choices[0].message.content)
            
            # Add metadata
            analysis['anomaly_score'] = anomaly_score
            analysis['analyzed_at'] = datetime.now().isoformat()
            analysis['llm_model'] = self.model
            
            return analysis
            
        except Exception as e:
            logger.error(f"LLM analysis failed: {str(e)}")
            # Fallback analysis
            return {
                'classification': 'unknown_anomaly',
                'confidence': 50,
                'risk_level': 'MEDIUM' if anomaly_score > 2 else 'LOW',
                'explanation': f'Anomalous behavior detected (score: {anomaly_score:.3f}). LLM analysis unavailable.',
                'immediate_actions': ['Monitor source IP', 'Review related logs'],
                'investigation_steps': ['Manual analysis required'],
                'anomaly_score': anomaly_score,
                'analyzed_at': datetime.now().isoformat(),
                'llm_model': 'fallback'
            }

class AlertManager:
    """Manages alerts and notifications"""
    
    def __init__(self):
        self.alert_thresholds = {
            'CRITICAL': 0,
            'HIGH': 5,
            'MEDIUM': 20,
            'LOW': 60
        }
        self.last_alert_times = {}
    
    def should_alert(self, threat_analysis: Dict) -> bool:
        """Determine if alert should be sent based on risk level and rate limiting"""
        risk_level = threat_analysis.get('risk_level', 'LOW')
        classification = threat_analysis.get('classification', 'unknown')
        
        # Check rate limiting
        now = datetime.now()
        alert_key = f"{classification}_{risk_level}"
        
        if alert_key in self.last_alert_times:
            minutes_since_last = (now - self.last_alert_times[alert_key]).total_seconds() / 60
            if minutes_since_last < self.alert_thresholds.get(risk_level, 60):
                return False
        
        self.last_alert_times[alert_key] = now
        return True
    
    async def send_alert(self, threat_analysis: Dict, log_entry: Dict):
        """Send alert through various channels"""
        if not self.should_alert(threat_analysis):
            return
        
        alert_data = {
            'timestamp': datetime.now().isoformat(),
            'risk_level': threat_analysis.get('risk_level'),
            'classification': threat_analysis.get('classification'),
            'confidence': threat_analysis.get('confidence'),
            'source_ip': log_entry.get('src_ip'),
            'target_ip': log_entry.get('dst_ip'),
            'explanation': threat_analysis.get('explanation'),
            'immediate_actions': threat_analysis.get('immediate_actions', [])
        }
        
        # Log alert
        logger.warning(f"SECURITY ALERT: {json.dumps(alert_data, indent=2)}")
        
        # Here you would integrate with:
        # - SIEM systems
        # - Slack/Teams notifications
        # - Email alerts
        # - Webhook endpoints
        # - Security orchestration platforms

class RealTimeThreatDetector:
    """Main threat detection pipeline"""
    
    def __init__(self, openai_api_key: str):
        self.feature_extractor = NetworkLogFeatureExtractor()
        self.isolation_forest = IsolationForest(contamination=0.1, random_state=42)
        self.autoencoder = None
        self.llm_analyzer = LLMThreatAnalyzer(openai_api_key)
        self.alert_manager = AlertManager()
        self.is_trained = False
        
        # Streaming components
        self.log_queue = Queue()
        self.processing_active = False
    
    def train_models(self, training_logs: List[Dict]):
        """Train anomaly detection models on historical normal data"""
        logger.info("Training models on historical data...")
        
        # Extract and transform features
        X_train = self.feature_extractor.fit_transform(training_logs)
        
        # Train Isolation Forest
        self.isolation_forest.fit(X_train)
        
        # Train Autoencoder
        self.autoencoder = AutoencoderAnomalyDetector(X_train.shape[1])
        self.autoencoder.train(X_train)
        
        self.is_trained = True
        logger.info("Models trained successfully!")
    
    def detect_anomaly(self, log_entry: Dict) -> Tuple[bool, float, str]:
        """Detect anomaly using ensemble of models"""
        if not self.is_trained:
            raise ValueError("Models must be trained before detection")
        
        # Transform log entry
        X = self.feature_extractor.transform(log_entry)
        
        # Isolation Forest prediction
        if_anomaly = self.isolation_forest.predict(X)[0] == -1
        if_score = -self.isolation_forest.score_samples(X)[0]  # Negative for anomaly score
        
        # Autoencoder prediction
        ae_anomaly, ae_score = self.autoencoder.predict_anomaly(X)
        
        # Ensemble decision (both models agree or high confidence from one)
        ensemble_anomaly = if_anomaly and ae_anomaly
        ensemble_score = (if_score + ae_score) / 2
        
        # Determine detection method
        if if_anomaly and ae_anomaly:
            method = "isolation_forest+autoencoder"
        elif if_anomaly:
            method = "isolation_forest"
        elif ae_anomaly:
            method = "autoencoder"
        else:
            method = "none"
        
        return ensemble_anomaly, ensemble_score, method
    
    async def process_log_entry(self, log_entry: Dict):
        """Process single log entry through the pipeline"""
        try:
            # Detect anomaly
            is_anomaly, anomaly_score, detection_method = self.detect_anomaly(log_entry)
            
            if is_anomaly:
                logger.info(f"Anomaly detected! Score: {anomaly_score:.3f}, Method: {detection_method}")
                
                # Get additional context (recent logs from same IP, etc.)
                context = await self.get_threat_context(log_entry)
                
                # LLM analysis
                threat_analysis = self.llm_analyzer.analyze_threat(log_entry, anomaly_score, context)
                
                # Send alerts if necessary
                await self.alert_manager.send_alert(threat_analysis, log_entry)
                
                return {
                    'timestamp': datetime.now().isoformat(),
                    'log_entry': log_entry,
                    'anomaly_detected': True,
                    'anomaly_score': anomaly_score,
                    'detection_method': detection_method,
                    'threat_analysis': threat_analysis
                }
            else:
                return {
                    'timestamp': datetime.now().isoformat(),
                    'log_entry': log_entry,
                    'anomaly_detected': False,
                    'anomaly_score': anomaly_score
                }
                
        except Exception as e:
            logger.error(f"Error processing log entry: {str(e)}")
            return None
    
    async def get_threat_context(self, log_entry: Dict) -> Dict:
        """Get additional context for threat analysis"""
        # In a real implementation, this would query:
        # - Historical logs from the same IP
        # - Threat intelligence feeds
        # - Internal asset information
        # - Previous incidents
        
        context = {
            'src_ip_history': f"Previous connections from {log_entry.get('src_ip', 'unknown')}",
            'target_asset_info': f"Information about target {log_entry.get('dst_ip', 'unknown')}",
            'recent_alerts': "Related recent security alerts",
            'threat_intel': "Relevant threat intelligence data"
        }
        return context
    
    async def stream_processor(self):
        """Main streaming processor loop"""
        logger.info("Starting stream processor...")
        self.processing_active = True
        
        while self.processing_active:
            try:
                if not self.log_queue.empty():
                    log_entry = self.log_queue.get()
                    result = await self.process_log_entry(log_entry)
                    
                    if result and result.get('anomaly_detected'):
                        logger.info(f"Threat processed: {result['threat_analysis']['classification']}")
                
                await asyncio.sleep(0.01)  # Small delay to prevent CPU spinning
                
            except Exception as e:
                logger.error(f"Stream processing error: {str(e)}")
                await asyncio.sleep(1)
    
    def add_log_entry(self, log_entry: Dict):
        """Add log entry to processing queue"""
        self.log_queue.put(log_entry)
    
    def stop_processing(self):
        """Stop the stream processor"""
        self.processing_active = False

# Example usage and testing
def generate_sample_logs(num_normal: int = 1000, num_anomalous: int = 50) -> List[Dict]:
    """Generate sample log entries for testing"""
    logs = []
    
    # Generate normal logs
    for _ in range(num_normal):
        log = {
            'timestamp': datetime.now() - timedelta(minutes=np.random.randint(0, 10080)),  # Last week
            'src_ip': f"192.168.1.{np.random.randint(1, 254)}",
            'dst_ip': f"10.0.1.{np.random.randint(1, 254)}",
            'src_port': np.random.choice([80, 443, 22, 21, 25, 53, 993, 995]),
            'dst_port': np.random.choice([80, 443, 22, 21, 25, 53]),
            'protocol': np.random.choice(['HTTP', 'HTTPS', 'SSH', 'FTP', 'SMTP', 'DNS']),
            'packet_size': np.random.normal(1500, 500),
            'duration': np.random.exponential(2),
            'bytes_sent': np.random.normal(5000, 2000),
            'bytes_received': np.random.normal(15000, 5000),
            'request_rate': np.random.normal(10, 3),
            'error_rate': np.random.normal(0.02, 0.01),
            'response_code': np.random.choice([200, 201, 301, 302, 404], p=[0.7, 0.1, 0.05, 0.05, 0.1]),
            'src_country': np.random.choice(['US', 'CA', 'UK', 'DE', 'FR']),
            'user_agent_category': np.random.choice(['browser', 'mobile', 'crawler', 'api']),
            'http_method': np.random.choice(['GET', 'POST', 'PUT', 'DELETE'], p=[0.6, 0.3, 0.05, 0.05])
        }
        logs.append(log)
    
    # Generate anomalous logs
    for _ in range(num_anomalous):
        anomaly_type = np.random.choice(['port_scan', 'brute_force', 'ddos', 'unusual_size'])
        
        if anomaly_type == 'port_scan':
            log = {
                'timestamp': datetime.now() - timedelta(minutes=np.random.randint(0, 60)),
                'src_ip': f"203.0.113.{np.random.randint(1, 254)}",  # External IP
                'dst_ip': f"10.0.1.{np.random.randint(1, 254)}",
                'src_port': np.random.randint(1024, 65535),
                'dst_port': np.random.randint(1, 1024),  # Scanning low ports
                'protocol': 'TCP',
                'packet_size': np.random.normal(64, 10),  # Small packets
                'duration': 0.1,  # Very short duration
                'bytes_sent': 100,
                'bytes_received': 0,
                'request_rate': 100,  # High rate
                'error_rate': 0.8,  # High error rate
                'response_code': 0,
                'src_country': np.random.choice(['CN', 'RU', 'KP']),
                'user_agent_category': 'scanner',
                'http_method': 'GET'
            }
        elif anomaly_type == 'brute_force':
            log = {
                'timestamp': datetime.now() - timedelta(minutes=np.random.randint(0, 30)),
                'src_ip': f"198.51.100.{np.random.randint(1, 254)}",
                'dst_ip': f"10.0.1.{np.random.randint(1, 10)}",  # Targeting few servers
                'src_port': np.random.randint(1024, 65535),
                'dst_port': 22,  # SSH
                'protocol': 'SSH',
                'packet_size': 200,
                'duration': 5,
                'bytes_sent': 500,
                'bytes_received': 200,
                'request_rate': 50,  # High rate
                'error_rate': 0.95,  # Very high error rate
                'response_code': 401,
                'src_country': np.random.choice(['CN', 'RU']),
                'user_agent_category': 'bot',
                'http_method': 'POST'
            }
        else:  # DDoS or unusual size
            log = {
                'timestamp': datetime.now() - timedelta(minutes=np.random.randint(0, 5)),
                'src_ip': f"{np.random.randint(1, 223)}.{np.random.randint(1, 254)}.{np.random.randint(1, 254)}.{np.random.randint(1, 254)}",
                'dst_ip': f"10.0.1.{np.random.randint(1, 5)}",
                'src_port': np.random.randint(1024, 65535),
                'dst_port': 80,
                'protocol': 'HTTP',
                'packet_size': np.random.normal(10000, 2000),  # Large packets
                'duration': 0.5,
                'bytes_sent': np.random.normal(50000, 10000),  # Large amounts
                'bytes_received': np.random.normal(100000, 20000),
                'request_rate': 200,  # Very high rate
                'error_rate': 0.1,
                'response_code': 200,
                'src_country': 'XX',
                'user_agent_category': 'bot',
                'http_method': 'GET'
            }
        
        logs.append(log)
    
    return logs

async def main():
    """Main function to demonstrate the threat detection system"""
    # Initialize the detector (you'll need to provide your OpenAI API key)
    OPENAI_API_KEY = "your-openai-api-key-here"  # Replace with actual key
    detector = RealTimeThreatDetector(OPENAI_API_KEY)
    
    # Generate sample data
    logger.info("Generating sample data...")
    all_logs = generate_sample_logs(1000, 50)
    
    # Split into training and test data
    train_logs = [log for log in all_logs if 'anomaly_type' not in log][:800]  # Normal logs for training
    test_logs = all_logs[800:]  # Mix of normal and anomalous for testing
    
    # Train models
    detector.train_models(train_logs)
    
    # Start stream processor
    processor_task = asyncio.create_task(detector.stream_processor())
    
    # Simulate real-time log stream
    logger.info("Starting real-time processing simulation...")
    
    for i, log_entry in enumerate(test_logs):
        detector.add_log_entry(log_entry)
        
        # Simulate realistic timing
        await asyncio.sleep(0.1)
        
        if i % 50 == 0:
            logger.info(f"Processed {i} log entries...")
    
    # Let processor catch up
    await asyncio.sleep(5)
    
    # Stop processing
    detector.stop_processing()
    processor_task.cancel()
    
    logger.info("Threat detection simulation completed!")

if __name__ == "__main__":
    # For testing without OpenAI API key
    print("Real-Time Threat Detection System")
    print("==================================")
    print()
    print("This system includes:")
    print("1. Feature extraction from network logs")
    print("2. Isolation Forest anomaly detection")
    print("3. Autoencoder-based deep anomaly detection")
    print("4. LLM-powered threat classification and explanation")
    print("5. Real-time streaming pipeline")
    print("6. Alert management with rate limiting")
    print()
    print("To run the full system:")
    print("1. Install required packages: tensorflow, scikit-learn, openai, kafka-python, redis")
    print("2. Set up OpenAI API key")
    print("3. Configure Kafka/Redis for production streaming")
    print("4. Run: python threat_detection_pipeline.py")
    print()
    print("For production deployment, also configure:")
    print("- SIEM integration")
    print("- Alert channels (Slack, email, webhooks)")
    print("- Threat intelligence feeds")
    print("- Model retraining pipeline")
    print("- Performance monitoring")
