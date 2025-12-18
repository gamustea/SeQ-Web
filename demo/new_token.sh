#!/bin/bash

# 1. Login y guardar tokens
echo "=== Login inicial ==="
RESPONSE=$(curl -s -X POST http://localhost:5000/oauth/token \
  -H "Content-Type: application/json" \
  -d '{
    "grant_type": "password",
    "username": "gmusteata",
    "password": "1234"
  }')

ACCESS_TOKEN=$(echo $RESPONSE | jq -r '.access_token')
REFRESH_TOKEN=$(echo $RESPONSE | jq -r '.refresh_token')

echo "Access Token: ${ACCESS_TOKEN:0:50}..."
echo "Refresh Token: ${REFRESH_TOKEN:0:50}..."

# 2. Usar el access token
echo -e "\n=== Usando access token ==="
curl -s http://localhost:5000/scans/results \
  -H "Authorization: Bearer $ACCESS_TOKEN" | jq

# 3. Esperar a que expire (o simular expiración)
echo -e "\n=== Esperando expiración del token... ==="
sleep 5

# 4. Refrescar el token
echo -e "\n=== Refrescando token ==="
NEW_RESPONSE=$(curl -s -X POST http://localhost:5000/oauth/token \
  -H "Content-Type: application/json" \
  -d "{
    \"grant_type\": \"refresh_token\",
    \"refresh_token\": \"$REFRESH_TOKEN\"
  }")

NEW_ACCESS_TOKEN=$(echo $NEW_RESPONSE | jq -r '.access_token')

echo "Nuevo Access Token: ${NEW_ACCESS_TOKEN:0:50}..."

# 5. Usar el nuevo access token
echo -e "\n=== Usando nuevo access token ==="
curl -s http://localhost:5000/scans/results \
  -H "Authorization: Bearer $NEW_ACCESS_TOKEN" | jq
