#!bin/sh

echo -e "\e[92m Add rule: defaultRule"
curl --request POST \
  --url http://localhost:8080/api/rule \
  --header 'content-type: application/json' \
  --data '{
  "name":"default rule",
  "rule":"rule DefaultRule\r\n{\r\n strings:\r\n  $a0 = \"default\" nocase\r\n condition:\r\n  $a0 \r\n}"
  }' \
  -u admin:root
