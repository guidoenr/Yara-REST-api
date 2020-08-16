#!bin/sh

echo -e "\e[93m Analyze file: /root/workspace/challenge_yara_guidoenr4/bash-scripts/analyzeFiles/file.txt"

curl -X POST \
  http://localhost:8080/api/analyze/file \
  -H 'content-type: multipart/form-data; boundary=----WebKitFormBoundary7MA4YWxkTrZu0gW' \
  -F file='@/root/workspace/challenge_yara_guidoenr4/bash-scripts/analyzeFiles/file.txt' \
  -F 'rules=0,1,2,3,4'

