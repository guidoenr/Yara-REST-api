curl --request POST \
  --url http://localhost:8080/api/analyze/text \
  --header 'content-type: application/json' \
  --data '{
	"text":"TOKEN_2016-02-03_112332",
	"rules": [
		{
			"rule_id": 0
		},
		{
			"rule_id": 1
		}
	]
}'
