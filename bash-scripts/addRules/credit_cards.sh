#!bin/sh

echo -e "\e[92m Add rule : creditCardRule"
curl --request POST \
  --url http://localhost:8080/api/rule \
  --header 'content-type: application/json' \
  --data '{
  "name":"credit card rule",
  "rule":"rule CreditCardRule\r\n{\r\n strings:\r\n  $a0 = /[0-9]{4}(-)?[0-9]{4}(-)?[0-9]{4}(-)?[0-9]{4}/\r\n condition:\r\n  $a0\r\n}"
  }' \
  -u admin:root
