echo -e "\e[93m Analyze text : defaultext"

curl --request POST \
  --url http://localhost:8080/api/analyze/text \
  --header 'content-type: application/json' \
  --data '{
	"text":"virus",
	"rules": [
		{
			"rule_id": 0
		},
		{
			"rule_id": 1
		}
	]
}'
