echo -e "\e[93m Analyze text : $1 "
sleep 1

curl --request POST \
  --url http://localhost:8080/api/analyze/text \
  --header 'content-type: application/json' \
  --data '{
	"text":"$1",
	"rules": [
		{
			"rule_id": 0
		},
		{
			"rule_id": 1
		}
	]
}'
