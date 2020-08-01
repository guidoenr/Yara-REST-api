import unittest, requests
from main import app

class BasicTests(unittest.TestCase):
    def setUp(self):
        app.config['TESTING'] = True
        app.config['WTF_CSRF_ENABLED'] = False
        app.config['DEBUG'] = False
        self.app = app.test_client()

    def test_main_page(self):
        response_ok = {
            "message": "guidoenr4 yara_challenge - meli"
        }
        response = requests.get('http://localhost:8080/')
        self.assertEqual(response_ok, response.json())

    def test_get_rules_tests(self):
        response = requests.get('http://localhost:8080/rules', auth=('admin', 'root'))
        self.assertEqual(200, response.status_code)

    def test_get_the_default_rule(self):
        data = {
            'rule': {'id': 0,
                     'name': 'defaultRule',
                     'rule': 'rule defaultRule\r\n'
                             '{\r\n'
                             ' strings:\r\n'
                             ' $my_text_string = "defaultrule"\r\n'
                             ' condition:\r\n'
                             ' $my_text_string\r\n'
                             '}'}
        }
        response = requests.get('http://localhost:8080/rules/defaultRule')
        self.assertEqual(data, response.json())

class AddRulesTest(unittest.TestCase):
    def test_add_rule_without_autentication(self):
        ruledata = {
            "name": "access token rule",
            "rule": "rule AccesToken\r\n{\r\n strings:\r\n $a0 = \"TOKEN_\"\r\n $a1 = \"TOKEN\"\r\n condition:\r\n   any of them\r\n}"
        }
        response = requests.post('http://localhost:8080/api/rule', auth=('user', 'normal'), data=ruledata)
        self.assertEqual(401, response.status_code)

    def test_add_rule_with_autentication(self):
        rule_request = {
            'name': 'access token rule',
            'rule': 'rule AccesToken\r\n{\r\n strings:\r\n $a0 = \"TOKEN_\"\r\n $a1 = \"TOKEN\"\r\n condition:\r\n   any of them\r\n}'
        }
        response_ok = {
            'id': 1,
            'name': "access token rule",
            'rule': 'rule AccesToken\r\n{\r\n strings:\r\n $a0 = \"TOKEN_\"\r\n $a1 = \"TOKEN\"\r\n condition:\r\n   any of them\r\n}'
        }

        response = requests.post('http://localhost:8080/api/rule', auth=('admin', 'root'), json= rule_request)
        self.assertEqual(response_ok, response.json())

    def test_add_token_rule(self):
        rule_request = {
            'name': 'old token rule',
            'rule': "rule oldToken\r\n{\r\n strings:\r\n $a0 = \"2016-02\"\r\n $a1 = \"2017-\"\r\n $a2 = \"2018-\"\r\n $a3 = \"2019-\"\r\n $a4 = \"2020-\"\r\n condition:\r\n   any of them\r\n}"
        }
        response_ok = {
            'id': 2,
            'name': "old token rule",
            "rule": "rule oldToken\r\n{\r\n strings:\r\n $a0 = \"2016-02\"\r\n $a1 = \"2017-\"\r\n $a2 = \"2018-\"\r\n $a3 = \"2019-\"\r\n $a4 = \"2020-\"\r\n condition:\r\n   any of them\r\n}"
        }
        response = requests.post('http://localhost:8080/api/rule', auth=('admin', 'root'), json=rule_request)
        self.assertEqual(response_ok, response.json())


class AnalyzeTextTest(unittest.TestCase):
    def test_the_text_is_secure(self):
        text_data = {
            "text": "esto es un texto a analizar",
            "rules": [{"rule_id": 0}]
        }
        response_ok = {
            'status': 'ok',
            'results': [{'rule_id': 0, 'matched': False}]
        }
        response = requests.post('http://localhost:8080/api/analyze/text', json= text_data)
        self.assertEqual(response_ok, response.json())

    def test_the_text_is_a_token(self):
        text_data = {
            "text": "TOKEN_2014-06-03_112332",
            "rules": [{"rule_id": 1}]
        }
        response_ok = {
            'status': 'ok',
            'results': [{'rule_id': 1, 'matched': True}]
        }
        response = requests.post('http://localhost:8080/api/analyze/text', json=text_data)
        self.assertEqual(response_ok, response.json())

    def test_the_token_is_older_than_january_2016(self):
        text_data = {
            "text": "TOKEN_2017-06-03_112332",
            "rules": [{"rule_id": 2}]
        }
        response_ok = {
            'status': 'ok',
            'results': [{'rule_id': 2, 'matched': True}]
        }
        response = requests.post('http://localhost:8080/api/analyze/text', json=text_data)
        self.assertEqual(response_ok, response.json())