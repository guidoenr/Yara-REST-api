#!bin/sh

echo -e "\e[92m Add rule : el token se creo despues del 31 de enero de 2016"
curl --request POST \
  --url http://localhost:8080/api/rule \
  --header 'content-type: application/json' \
  --data '{
  "name":"old token rule",
  "rule":"rule OldToken\r\n{\r\n strings:\r\n $a0 = \"2016-02\"\r\n $a1 = \"2016-01-31\"\r\n $a2 = \"2017-\"\r\n $a3 = \"2018-\"\r\n $a4 = \"2019-\"\r\n $a5 = \"2020-\"\r\n condition:\r\n   any of them\r\n}"
  }' \
  -u admin:root

