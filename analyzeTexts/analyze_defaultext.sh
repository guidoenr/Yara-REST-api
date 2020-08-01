#!bin/sh

echo -e "\e[93m Analyze text : defualtext"

curl --request POST \
  --url http://localhost:8080/api/analyze/text \
  --header 'content-type: application/json' \
  --data '{
	"text":"defualtext",
	"rules": [
		{
			"rule_id": 0
		}
		 ]
}'
