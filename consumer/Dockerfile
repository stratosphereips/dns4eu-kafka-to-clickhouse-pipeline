FROM python:3.11-slim

WORKDIR /app

COPY . /app

# Install dependencies
RUN pip install kafka-python clickhouse-driver tenacity

CMD ["python", "consumer.py"]
