# Model Deployment

Used to deploy the ML models for intrusion detection.

- `models`: Models used for the `deployment`. Change these on retraining.
- `predictions`: Classes used to load the model and do predictions. Change these on retraining.
- `consumer.py`: Running the `network-flows` topic consumer for port scan and DoS Slowloris predictions.
- `Dockerfile`: The Dockerfile used for building Docker image.
- `requirements.txt`: The dependencies for deploying the consumer.

## Building

```bash
docker build -t prediction .
```
