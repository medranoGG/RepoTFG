FROM ubuntu:22.04

LABEL authors="Gabriel"

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 \
    python3-pip \
    python3-dev \
    build-essential \
    wget \
    curl \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

COPY tfg_api.py tfg_code.py requirements.txt /app/

RUN pip3 install --no-cache-dir -r requirements.txt

EXPOSE 5000

ENTRYPOINT ["python3", "tfg_api.py"]


