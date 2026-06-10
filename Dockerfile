FROM python:3.12-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt ./
RUN python -m pip install --upgrade pip
RUN pip install --no-cache-dir -r requirements.txt
RUN python -m playwright install chromium

COPY . /app

ENTRYPOINT ["python", "main.py"]
