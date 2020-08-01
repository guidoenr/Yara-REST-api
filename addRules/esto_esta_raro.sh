#!bin/sh

echo -e "\e[92m Add rule : esto esta raro"
curl --request POST \
  --url http://localhost:8080/api/rule \
  --header 'content-type: application/json' \
  --data '{
  "name":"esto esta raro ",
  "rule":"rule estoEstaRaroRule\r\n{\r\n strings:\r\n $my_text_string = \"raro\"\r\n condition:\r\n   $my_text_string\r\n}"
  }' \
  -u admin:root