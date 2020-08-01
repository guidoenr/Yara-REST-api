#!bin/sh

echo -e "\e[92m Add rule : is a acces token"
sleep 1
curl --request POST \
  --url http://localhost:8081/api/rule \
  --header 'content-type: application/json' \
  --data '{
  "name":"access token rule",
  "rule":"rule AccesToken\r\n{\r\n strings:\r\n $a0 = \"TOKEN_\"\r\n $a1 = \"TOKEN\"\r\n condition:\r\n   any of them\r\n}"
  }'
