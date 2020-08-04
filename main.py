#@autor : github.com/guidoenr4

import os, ast
import yara
from flask import Flask, jsonify, request
from rules import rulesList
from flask_httpauth import HTTPBasicAuth
from werkzeug.security import generate_password_hash, check_password_hash
app = Flask(__name__)
auth = HTTPBasicAuth()


#--------------------------------------------------LOGGIN- AUTENTICATION ------------------------#
users = {
    'admin': generate_password_hash('root'),
    'guido': generate_password_hash('mercadolibre')
}

@auth.verify_password
def verify_password(username, password):
    if username in users and \
            check_password_hash(users.get(username), password):
        return username

#-------------------------------------------------- GET -----------------------------------------#
@app.route('/')
def host():
    print('Index returned Succesfuly')
    return "Hello, Friend :) Bienvenido al meli-challenge de Guido Enrique", 200

@app.route('/rules', methods=['GET'])
@auth.login_required()
def getRules():
    return jsonify(rulesList), 200

@app.route('/rules/<string:rule_name>', methods=['GET'])
@auth.login_required()
def getRule(rule_name):
    rulesFound = [rule for rule in rulesList if rule['name'] == rule_name] #barrido a la lista para ver la rule que piden
    if len(rulesFound) > 0:
        return jsonify({'rule': rulesFound[0]}), 200 # retorno la rule encontrada
    else:
        return jsonify({'message': "Rule not found"}), 404

#------------------------------------------------- POST ------------------------------------------#
@app.route('/api/rule', methods = ['POST'])
@auth.login_required()
def addRule(): # se borran cuando el server se reinicia
    try:
        name = request.json['name']
        rule = request.json['rule']
    except KeyError as e:
        return jsonify({'status': str(KeyError)}), 409
    else:
        id = len(rulesList)
        new_rule = {
            'name': name,
            'rule': rule,
            'id': id
        }
        if the_rule_already_exist(name):
            return "The rule " + name + "already exist", 409
        else:
            rulesList.append(new_rule)
            compileRule(new_rule['rule'])
            return jsonify({'id': id, 'name': new_rule['name'], 'rule': new_rule['rule']}), 201

@app.route('/api/analyze/text', methods = ['POST'])
def analyzeText():
   try:
       text = request.json['text']
       rules = request.json['rules']
   except KeyError as e:
       return jsonify({'status:': str(KeyError)}), 409
   else:
       responseBody = {'status': 'ok', 'results': []}
       for rule in rules:
           responseBody['results'].append(theTextPassTheRule(text, rule['rule_id']))
       return responseBody, 200


ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif'}
@app.route('/api/analyze/file', methods = ['POST'])
def analyzeFile():
    try:
        contentType = request.headers['content-type']
        rules = ast.literal_eval('[' + request.form['rules'] + ']') #converting to list
        file = request.files['file']
        extension = file.filename.split('.')
        ALLOWED_EXTENSIONS.__contains__(extension[1])
    except KeyError as e:
        return jsonify({'status:': str(KeyError)}), type(e).__name__, 409
    else:
        responseBody={'status': 'ok', 'results': []}
        for ruleid in rules:
            responseBody['results'].append(theFilePassTheRule(file, ruleid))
        return responseBody, 200

#--------------------------------------------------TOOLS-------------------------------------------#
def the_rule_already_exist(rulename):
    for rule in rulesList:
        if rule['name'] == rulename:
            return True
    return False


def compileRule(rule):
    try:
        rules = yara.compile(source=rule)
        rules.save('compiled-rules/myrules')
    except:
        print("error compiling the rule")

def loadCurrentRules():
    try:
        rules = yara.load('compiled-rules/myrules')
    except:
        print("Error loading the  current rules")

def findRuleById(id):
    for rule in rulesList:
        if rule['id'] == id:
            return rule['rule']

def compileCurrentRules():
    for element in rulesList:
        try:
            compileRule(element['rule'])
        except:
            print("error compiling the rules")

def theTextPassTheRule(text, rule_id):
    rule = findRuleById(rule_id)
    if rule == None:
        return {'rule_id': rule_id, 'matched': 'error', 'cause': 'the rule ' + str(rule_id) + ' doesnt exist'}
    else:
        rules = yara.compile(source=rule)
        filepath = text + '.txt'
        f = open(filepath, 'w') #yara si o si te obliga a hacer un file, no lo podes hacer con un string de python
        f.write(text)
        f.close()
        match = rules.match(filepath)
        x = len(match) > 0
        os.remove(filepath)
        return {'rule_id': rule_id, 'matched': x}

def theFilePassTheRule(file, rule_id):
    rule = findRuleById(rule_id)
    if rule is None:
        return {'rule_id': rule_id, 'matched': 'error', 'cause': 'the rule ' + str(rule_id) + ' doesnt exist'}
    else:
        rules = yara.compile(source=rule)
        match = rules.match(data=file.read())
        x = len(match) > 0
        return {'rule_id': rule_id, 'matched': x}

if __name__ == '__main__':
    compileCurrentRules()
    loadCurrentRules()
    app.run(debug=False, port=8080, host="0.0.0.0")









