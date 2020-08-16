#!bin/sh

echo -e "\e[92m Add rule : accesTokenRule"
curl --request POST \
  --url http://localhost:8080/api/rule \
  --header 'content-type: application/json' \
  --data '{
  "name":"access token rule",
  "rule":"rule AccessTokenRule\r\n{\r\n strings:\r\n  $a0 = /TOKEN_([0-9]){4}-([0-9]){2}-([0-9]){2}_([0-9])+/ nocase wide ascii\r\n condition:\r\n  $a0\r\n}"
  }' \
  -u admin:root

$a4 =  nocase wide ascii