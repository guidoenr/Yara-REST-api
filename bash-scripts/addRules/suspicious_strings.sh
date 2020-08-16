#!bin/sh

echo -e "\e[92m Add rule : SuspiciosStrings"
curl --request POST \
  --url http://localhost:8080/api/rule \
  --header 'content-type: application/json' \
  --data '{
  "name":"suspicios strings rule",
  "rule":"rule SuspiciosStringsRule\r\n{\r\n strings:\r\n  $a0 = \"backdoor\" nocase\r\n  $a1 = \"virus\" nocase\r\n condition:\r\n   any of them\r\n}"
  }' \
  -u admin:root


