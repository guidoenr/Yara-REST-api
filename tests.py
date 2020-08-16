import unittest, requests
from main import app

# Los tests compilan con el status default del servidor (5 reglas cargadas)

class BasicTests(unittest.TestCase):

    def setUp(self):
        app.config['TESTING'] = True
        app.config['WTF_CSRF_ENABLED'] = False
        app.config['DEBUG'] = False
        app.test_client()

    def test_get_rules(self):
        response = requests.get('http://localhost:8080/rules', auth=('admin', 'root'))
        self.assertEqual(200, response.status_code)

    def test_get_a_rule_that_doesnt_exist(self):
        responseBody = {'message': 'Rule not found'}
        response = requests.get('http://localhost:8080/rules/NotARule', auth=('admin', 'root'))
        self.assertEqual(responseBody, response.json())

    def test_get_a_existing_rule(self):
        responseBody = {
            'rule': {
                "name": "credit card rule",
                "rule": "rule CreditCardRule\r\n{\r\n strings:\r\n  $a0 = /[0-9]{4}(-)?[0-9]{4}(-)?[0-9]{4}(-)?[0-9]{4}/\r\n condition:\r\n  $a0\r\n}",
                "id": 2
            }
        }
        response = requests.get('http://localhost:8080/rules/credit card rule', auth=('admin', 'root'))
        self.assertEqual(responseBody,response.json())

class AddRulesTest(unittest.TestCase):

    def setUp(self):
        app.config['TESTING'] = True
        app.config['WTF_CSRF_ENABLED'] = False
        app.config['DEBUG'] = False
        self.app = app.test_client()

    def test_add_rule_that_exist(self):
        request = {
            "name": "access token rule",
            "rule": "rule AccesToken\r\n{\r\n strings:\r\n $a0 = \"TOKEN_\"\r\n $a1 = \"TOKEN\"\r\n condition:\r\n   any of them\r\n}"
        }
        response = requests.post('http://localhost:8080/api/rule', auth=('user', 'normal'), data= request)
        self.assertEqual(401, response.status_code)

    def test_add_rule_with_authentication(self):
        rule_request = {
            'name': 'a new rule',
            'rule': 'rule ANewRule\r\n{\r\n strings:\r\n $a0 = \"NewRule\"\r\n condition:\r\n   $a0\r\n}'
        }
        response_ok = {
            'id': 5,
            'name': "a new rule",
            'rule': 'rule ANewRule\r\n{\r\n strings:\r\n $a0 = \"NewRule\"\r\n condition:\r\n   $a0\r\n}'
        }

        response = requests.post('http://localhost:8080/api/rule', auth=('admin', 'root'), json= rule_request)
        self.assertEqual(response_ok, response.json())

    def test_add_rule_without_authentication(self):
        rule_request = {
            'name': 'a new rule',
            'rule': 'rule ANewRule\r\n{\r\n strings:\r\n $a0 = \"NewRule\"\r\n condition:\r\n   $a0\r\n}'
        }
        response = requests.post('http://localhost:8080/api/rule', auth=('normalUser', '1234'), json= rule_request)
        self.assertEqual(401, response.status_code) # 401 Unauthorized

class AnalyzeTextTest(unittest.TestCase):

    def setUp(self):
        app.config['TESTING'] = True
        app.config['WTF_CSRF_ENABLED'] = False
        app.config['DEBUG'] = False
        self.app = app.test_client()

    def test_the_text_is_secure(self):
        text_data = {
            "text": "esto es un texto a analizar",
            "rules": [{"rule_id": 0}, {"rule_id": 1}]
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
            "rules": [{"rule_id": 1}]
        }
        response_ok = {
            'status': 'ok',
            'results': [{'rule_id': 1, 'matched': True}]
        }
        response = requests.post('http://localhost:8080/api/analyze/text', json=text_data)
        self.assertEqual(response_ok, response.json())

    def test_the_rule_doesnt_exist(self):
        text_data = {
            "text": "untexto",
            "rules": [{"rule_id": 123}]
        }
        response_ok = {
            'status': 'ok',
            'results': [{'rule_id': 123, 'matched': 'error', 'cause': 'the rule 123 doesnt exist'}]
        }
        response = requests.post('http://localhost:8080/api/analyze/text', json=text_data)
        self.assertEqual(response_ok, response.json())

    def test_the_text_is_a_virus(self):
        text_data = {
            "text": "virus",
            "rules": [{"rule_id": 2}]
        }
        response_ok = {
            'status': 'ok',
            'results': [{'rule_id': 2, 'matched': True}]
        }
        response = requests.post('http://localhost:8080/api/analyze/text', json=text_data)
        self.assertEqual(response_ok, response.json())