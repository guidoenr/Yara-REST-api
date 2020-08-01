import main, unittest, requests
from main import app
from flask import jsonify

class BasicTests(unittest.TestCase):
    def setUp(self):
        app.config['TESTING'] = True
        app.config['WTF_CSRF_ENABLED'] = False
        app.config['DEBUG'] = False
        self.app = app.test_client()

    def test_main_page(self):
        data = b'{"message":"guidoenr4 yara_challenge - meli"}\n'
        response = requests.get('http://localhost:8080/')
        self.assertEqual(data, response.content)

    def test_get_rules_tests(self):
        response = requests.get('http://localhost:8080/rules', auth=('admin', 'root'))
        self.assertEqual(200,response.status_code)

    def test_get_the_default_rule(self):
        data = (b'{"rule":{"id":0,"name":"defaultRule","rule":"rule defaultRule\\r\\n{\\r\\n s'
        b'trings:\\r\\n $my_text_string = \\"defaultrule\\"\\r\\n condition:\\r\\n $my'
        b'_text_string\\r\\n}"}}\n')

        response = requests.get('http://localhost:8080/rules/defaultRule')
        self.assertEqual(data, response.content)

class AddRulesTest(unittest.TestCase):
    def test_add_rule_without_autentication(self):
        ruledata = {
            "name": "access token rule",
            "rule": "rule AccesToken\r\n{\r\n strings:\r\n $a0 = \"TOKEN_\"\r\n $a1 = \"TOKEN\"\r\n condition:\r\n   any of them\r\n}"
        }
        response = requests.post('http://localhost:8080/api/rule', auth=('user', 'normal'), data=ruledata)
        self.assertEqual(401, response.status_code)



