#!bin/sh

echo -e "\e[92m Add rule : el token se creo despues del 31 de enero de 2016"
curl --request POST \
  --url http://localhost:8080/api/rule \
  --header 'content-type: application/json' \
  --data '{
  "name":"old token rule",
  "rule":"rule OldTokenRule\r\n{\r\n strings:\r\n  $a1 = /TOKEN_2016-(0([2-9]){1}|1(0-2){1})-([0-9]){2}_([0-9])+/ nocase wide ascii \r\n  $a2 = /TOKEN_(201([7-9]){1}|20([2-9]){1}([0-9]){1})-([0-9]){2}-([0-9]){2}_([0-9])+/ nocase wide ascii \r\n condition:\r\n   any of them\r\n}"
  }' \
  -u admin:root

