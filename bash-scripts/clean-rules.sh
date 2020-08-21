echo -e "\e[92mRules removed succesfuly"

cd ../rules/

truncate -s 0 rules.json
truncate -s 0 saved_rules.yara

