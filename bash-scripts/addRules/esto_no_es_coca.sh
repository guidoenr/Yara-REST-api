#!bin/sh

echo -e "\e[92m Add rule : esto no es coca papi"
curl --request POST \
  --url http://localhost:8080/api/rule \
  --header 'content-type: application/json' \
  --data '{
  "name":"esto no es coca papi rule",
  "rule":"rule EstoNoEsCocaPapiRule\r\n{\r\n strings:\r\n  $my_text_string = \"esto no es coca papi\"\r\n condition:\r\n   $my_text_string\r\n}"
  }' \
  -u admin:root

