# Description: Test the API with a HTTP2 POST request

curl \
  --http1.1 \
  -H "x-pub-key: 7d5acf3d-032d-4fe3-b24d-eccba2f53c8d" \
  -H "x-api-key: 690c3205-54c3-4c09-8027-012708584db8" \
  -H "Content-Type: application/json" \
  --request POST \
  --data '{"query":"How big is the ocean?","context":""}' \
  http://127.0.0.1:3000/api/v2

