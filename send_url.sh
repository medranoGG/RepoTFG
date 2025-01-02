#!/bin/bash

# Verifica que se haya proporcionado una URL como argumento
if [ "$#" -ne 1 ]; then
  echo "Uso: $0 <URL>"
  exit 1
fi

# URL proporcionada por el usuario
URL=$1

# Realiza la solicitud a la API
RESPONSE=$(curl -s -X POST http://127.0.0.1:5000/url \
  -H "Content-Type: application/json" \
  -d "{\"url\":\"$URL\"}")

# Imprime la respuesta al usuario
echo "Respuesta de la API:"
echo "$RESPONSE"

