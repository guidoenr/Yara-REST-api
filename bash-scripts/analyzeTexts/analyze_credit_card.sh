#!/bin/bash
echo -e "\e[93m Analyze text : 1234 5678 9123 4567"

curl --request POST \
  --url http://localhost:8080/api/analyze/text \
  --header 'content-type: application/json' \
  --data '{
	"text":"2143123412341234" ,
	"rules": [
		{
			"rule_id": 0
		},
		{
			"rule_id": 4
		}
	]
}'
