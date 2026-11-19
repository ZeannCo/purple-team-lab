# HelpBot: deliberately vulnerable LLM agent for the purple team lab. Lab use only.
FROM python:3.12-slim

RUN apt-get update && apt-get install -y --no-install-recommends iputils-ping curl \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --create-home --uid 10001 helpbot

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app.py tools_server.py ./
COPY kb ./kb
COPY config ./config

USER helpbot
EXPOSE 8090
CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8090"]
