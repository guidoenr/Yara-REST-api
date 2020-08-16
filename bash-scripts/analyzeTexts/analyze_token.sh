#!/bin/bash
echo -e "\e[93m Analyze text : TOKEN_2014-06-03_112332"

curl --request POST \
  --url http://localhost:8080/api/analyze/text \
  --header 'content-type: application/json' \
  --data '{
	"text":"TOKEN_2014-06-03_112332" ,
	"rules": [
		{
			"rule_id": 2
		},
		{
			"rule_id": 3
		}
	]
}'
