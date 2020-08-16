echo -e "\e[92mRules removed succesfuly"

cd /root/workspace/challenge_yara_guidoenr4/rules/

truncate -s 0 rules.json
truncate -s 0 saved_rules.yara

