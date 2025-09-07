# Base image
FROM mcr.microsoft.com/python:3.11-slim

WORKDIR /app

# Sistem bağımlılıkları
RUN apt-get update && \
    apt-get install -y gcc g++ unixodbc-dev curl && \
    rm -rf /var/lib/apt/lists/*

# Python paketlerini yükle
COPY requirements.txt .
RUN pip install --upgrade pip
RUN pip install -r requirements.txt

# Uygulama dosyalarını ve entrypoint.sh'ı kopyala
COPY . .

# entrypoint scriptini çalıştırılabilir yap
RUN chmod +x entrypoint.sh

# Port ve buffer ayarı
ENV PORT=8000
ENV PYTHONUNBUFFERED=1

# Entrypoint
ENTRYPOINT ["./entrypoint.sh"]
