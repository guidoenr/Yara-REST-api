#!bin/sh

echo -e "\e[92m Add rule : el token se creo despues del 31 de enero de 2016"
curl --request POST \
  --url http://localhost:8080/api/rule \
  --header 'content-type: application/json' \
  --data '{
  "name":"old token rule",
  "rule":"rule oldToken\r\n{\r\n strings:\r\n $a0 = \"2016-02\"\r\n $a1 = \"2016-01-31\"\r\n condition:\r\n   any of them\r\n}"
  }' \
  -u admin:root