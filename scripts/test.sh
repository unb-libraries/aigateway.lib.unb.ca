# Description: Test the API with a HTTP2 POST request

curl \
  --http2-prior-knowledge \
  -H "x-pub-key: keyhere" \
  -H "x-api-key: keyhere" \
  -H "Content-Type: application/json" \
  --request POST \
  --data '{"query":"How big is the ocean?","context":""}' \
  http://127.0.0.1:3000/api/v2

