#!bin/sh

echo -e "\e[92m Add rule : SuspiciosStrings"
sleep 1
curl --request POST \
  --url http://localhost:8080/api/rule \
  --header 'content-type: application/json' \
  --data '{
  "name":"suspicios strings rule",
  "rule":"rule Misc_Suspicious_Strings\r\n{\r\n strings:\r\n $a0 = \"backdoor\"\r\n $a1 = \"virus\"\r\n condition:\r\n   any of them\r\n}"
  }'



