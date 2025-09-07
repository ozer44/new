#!/bin/sh
# entrypoint.sh

# Eğer .env varsa yükle
if [ -f .env ]; then
    echo "Loading .env file..."
    export $(grep -v '^#' .env | xargs)
fi

# Uygulamayı başlat
exec gunicorn --bind 0.0.0.0:8000 app:app
