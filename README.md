# Real-Time Threat Detection with LLM + Anomaly Models

A comprehensive streaming cybersecurity pipeline that combines machine learning anomaly detection (Isolation Forest + Autoencoder) with Large Language Model analysis to classify, explain, and alert on suspicious network or log activity in real time.

## 🔍 Overview

This system provides enterprise-grade threat detection capabilities by:
- **Detecting anomalies** using ensemble ML models (Isolation Forest + Deep Autoencoders)
- **Classifying threats** using LLM analysis for human-readable explanations
- **Processing logs in real-time** with async streaming architecture
- **Managing alerts** with intelligent rate limiting and risk-based filtering
- **Providing actionable insights** with detailed threat analysis and recommendations

## 🏗️ Architecture

```
Network Logs → Feature Extraction → Anomaly Detection → LLM Analysis → Alert Management
     ↓              ↓                    ↓                ↓              ↓
  Raw logs    Numerical/Categorical  Isolation Forest  GPT Analysis   SIEM/Slack/Email
              Features              + Autoencoder     Classification     Notifications
```

## 🚀 Features

### Anomaly Detection Models
- **Isolation Forest**: Statistical outlier detection for traditional anomaly patterns
- **Deep Autoencoder**: Neural network-based detection for complex behavioral anomalies
- **Ensemble Approach**: Combines both models for higher accuracy and lower false positives

### LLM-Powered Analysis
- **Threat Classification**: Categorizes detected anomalies into specific threat types
- **Risk Assessment**: Assigns risk levels (LOW, MEDIUM, HIGH, CRITICAL)
- **Explanation Generation**: Provides human-readable explanations of why behavior is suspicious
- **Actionable Recommendations**: Suggests immediate actions and investigation steps

### Real-Time Processing
- **Async Pipeline**: Non-blocking log processing for high throughput
- **Queue Management**: Efficient handling of high-volume log streams
- **Scalable Architecture**: Designed for enterprise-scale deployments

### Smart Alerting
- **Rate Limiting**: Prevents alert fatigue with intelligent throttling
- **Risk-Based Filtering**: Prioritizes alerts based on threat severity
- **Multiple Channels**: Supports SIEM, Slack, email, and webhook integrations

## 🛡️ Threat Detection Capabilities

| Threat Type | Description | Detection Method |
|-------------|-------------|------------------|
| **Brute Force** | Multiple failed login attempts | Pattern analysis + LLM validation |
| **Port Scanning** | Sequential port connection attempts | Traffic pattern anomalies |
| **DDoS Attacks** | High volume requests from multiple sources | Request rate + source diversity |
| **SQL Injection** | Malicious SQL patterns in requests | Content analysis + behavioral patterns |
| **Data Exfiltration** | Unusual data transfer patterns | Volume + timing anomalies |
| **Malware C&C** | Communication with command servers | Destination analysis + traffic patterns |
| **Privilege Escalation** | Attempts to gain higher privileges | Access pattern anomalies |
| **Lateral Movement** | Suspicious internal network activity | Internal traffic pattern analysis |

## 📋 Prerequisites

### System Requirements
- Python 3.8+
- 8GB+ RAM (for model training)
- Multi-core CPU recommended

### Required Python Packages
```bash
pip install tensorflow>=2.12.0
pip install scikit-learn>=1.3.0
pip install openai>=1.0.0
pip install pandas>=2.0.0
pip install numpy>=1.24.0
pip install asyncio
pip install aiohttp
pip install kafka-python
pip install aioredis
```

### External Services
- **OpenAI API Key** (for LLM analysis)
- **Kafka** (for production log streaming)
- **Redis** (for caching and state management)

## 🚀 Quick Start

### 1. Installation
```bash
# Clone or download the threat_detection_pipeline.py file
git clone <your-repo>
cd threat-detection

# Install dependencies
pip install -r requirements.txt
```

### 2. Configuration
```python
# Set your OpenAI API key
OPENAI_API_KEY = "sk-your-actual-openai-api-key-here"

# Update in threat_detection_pipeline.py
detector = RealTimeThreatDetector(OPENAI_API_KEY)
```

### 3. Basic Usage
```python
import asyncio
from threat_detection_pipeline import RealTimeThreatDetector

async def main():
    # Initialize detector
    detector = RealTimeThreatDetector("your-openai-api-key")
    
    # Train on historical normal data
    training_logs = load_your_normal_logs()  # Your data loading function
    detector.train_models(training_logs)
    
    # Start real-time processing
    processor_task = asyncio.create_task(detector.stream_processor())
    
    # Add logs for analysis
    detector.add_log_entry({
        'timestamp': '2024-01-15T10:30:00Z',
        'src_ip': '192.168.1.100',
        'dst_ip': '10.0.1.50',
        'src_port': 12345,
        'dst_port': 22,
        'protocol': 'SSH',
        'bytes_sent': 500,
        'bytes_received': 200,
        # ... other log fields
    })
    
    # Let it process
    await asyncio.sleep(10)
    
    # Stop processing
    detector.stop_processing()

# Run the detector
asyncio.run(main())
```

### 4. Run Demo
```bash
python threat_detection_pipeline.py
```

## 📊 Log Format

The system expects network logs in the following JSON format:

```json
{
    "timestamp": "2024-01-15T10:30:00Z",
    "src_ip": "192.168.1.100",
    "dst_ip": "10.0.1.50",
    "src_port": 12345,
    "dst_port": 80,
    "protocol": "HTTP",
    "packet_size": 1500,
    "duration": 2.5,
    "bytes_sent": 5000,
    "bytes_received": 15000,
    "request_rate": 10,
    "error_rate": 0.02,
    "response_code": 200,
    "src_country": "US",
    "user_agent_category": "browser",
    "http_method": "GET"
}
```

### Required Fields
- `timestamp`: ISO 8601 formatted timestamp
- `src_ip`, `dst_ip`: Source and destination IP addresses
- `src_port`, `dst_port`: Source and destination ports
- `protocol`: Network protocol (HTTP, HTTPS, SSH, etc.)

### Optional Fields
- `packet_size`, `duration`, `bytes_sent`, `bytes_received`: Traffic metrics
- `request_rate`, `error_rate`: Rate-based metrics
- `response_code`: HTTP response code
- `src_country`: Source country code
- `user_agent_category`: Browser, mobile, bot, etc.
- `http_method`: GET, POST, PUT, DELETE

## 🔧 Configuration

### Model Parameters
```python
# Isolation Forest
contamination = 0.1  # Expected proportion of outliers

# Autoencoder
encoding_dim = 32    # Latent space dimension
epochs = 50          # Training epochs
threshold_percentile = 95  # Anomaly threshold

# LLM Analysis
model = "gpt-3.5-turbo"  # OpenAI model
temperature = 0.1         # Response randomness
```

### Alert Thresholds
```python
alert_thresholds = {
    'CRITICAL': 0,   # Immediate alerts
    'HIGH': 5,       # Max 1 alert per 5 minutes
    'MEDIUM': 20,    # Max 1 alert per 20 minutes
    'LOW': 60        # Max 1 alert per hour
}
```

## 🔌 Production Deployment

### 1. Kafka Integration
```python
# Add Kafka consumer for real-time log ingestion
from kafka import KafkaConsumer

consumer = KafkaConsumer(
    'security-logs',
    bootstrap_servers=['localhost:9092'],
    value_deserializer=lambda x: json.loads(x.decode('utf-8'))
)

for message in consumer:
    detector.add_log_entry(message.value)
```

### 2. Redis Caching
```python
# Add Redis for state management and caching
import aioredis

redis = await aioredis.create_redis_pool('redis://localhost')
```

### 3. SIEM Integration
```python
# Example Splunk integration
async def send_to_siem(alert_data):
    splunk_url = "https://your-splunk-instance/services/collector"
    headers = {"Authorization": "Splunk your-hec-token"}
    
    async with aiohttp.ClientSession() as session:
        await session.post(splunk_url, json=alert_data, headers=headers)
```

### 4. Container Deployment
```dockerfile
FROM python:3.9-slim

WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt

COPY threat_detection_pipeline.py .
CMD ["python", "threat_detection_pipeline.py"]
```

## 📈 Monitoring & Metrics

### Key Metrics to Track
- **Processing Rate**: Logs processed per second
- **Anomaly Detection Rate**: Percentage of logs flagged as anomalous
- **False Positive Rate**: Manually verified false positives
- **Alert Response Time**: Time from detection to alert
- **Model Performance**: Precision, recall, F1-score

### Health Checks
```python
# Add health check endpoint
@app.route('/health')
def health_check():
    return {
        'status': 'healthy',
        'models_trained': detector.is_trained,
        'processing_active': detector.processing_active,
        'queue_size': detector.log_queue.qsize()
    }
```

## 🔒 Security Considerations

- **API Key Management**: Use environment variables or secret management systems
- **Data Privacy**: Ensure log data is handled according to privacy regulations
- **Access Control**: Implement proper authentication for system access
- **Audit Logging**: Log all system actions and decisions
- **Model Security**: Protect trained models from unauthorized access

## 🐛 Troubleshooting

### Common Issues

**Models not training properly**
```bash
# Check data format and feature extraction
python -c "from threat_detection_pipeline import NetworkLogFeatureExtractor; fe = NetworkLogFeatureExtractor(); print('Feature extractor loaded')"
```

**High memory usage**
```python
# Reduce batch size or model complexity
autoencoder = AutoencoderAnomalyDetector(input_dim, encoding_dim=16)  # Smaller encoding
```

**OpenAI API errors**
```python
# Add retry logic and fallback analysis
try:
    analysis = self.llm_analyzer.analyze_threat(log_entry, anomaly_score)
except Exception as e:
    analysis = fallback_analysis(log_entry, anomaly_score)
```

**Queue overflow**
```python
# Implement queue size limiting
if self.log_queue.qsize() < MAX_QUEUE_SIZE:
    self.log_queue.put(log_entry)
else:
    logger.warning("Queue full, dropping log entry")
```

## 📚 API Reference

### RealTimeThreatDetector

#### Methods
- `train_models(training_logs)`: Train anomaly detection models
- `detect_anomaly(log_entry)`: Detect anomalies in single log entry
- `process_log_entry(log_entry)`: Full pipeline processing
- `add_log_entry(log_entry)`: Add log to processing queue
- `stream_processor()`: Main async processing loop

### NetworkLogFeatureExtractor

#### Methods
- `extract_features(log_entry)`: Extract features from log
- `fit_transform(logs)`: Fit encoders and transform training data
- `transform(log_entry)`: Transform single log for prediction

### LLMThreatAnalyzer

#### Methods
- `analyze_threat(log_entry, anomaly_score, context)`: Analyze threat using LLM

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Add tests for new functionality
4. Ensure all tests pass
5. Submit a pull request

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🙋 Support

For issues and questions:
- Create an issue in the repository
- Check troubleshooting section
- Review logs for error details

## 🔄 Version History

- **v1.0.0**: Initial release with Isolation Forest + Autoencoder + LLM analysis
- **v1.1.0**: Added real-time streaming capabilities
- **v1.2.0**: Enhanced alert management and rate limiting
- **v1.3.0**: Production deployment features and monitoring

---

**Built with ❤️ for cybersecurity professionals**
