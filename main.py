# @autor : github.com/guidoenr4

import os, ast, yara, json
from bcolors import Bcolors
from flask import Flask, jsonify, request
from flask_httpauth import HTTPBasicAuth
from werkzeug.security import generate_password_hash, check_password_hash



# -------------------------------------------------- CLASS ------------------------#
app = Flask(__name__)
auth = HTTPBasicAuth()
rulesPath = '/root/workspace/challenge_yara_guidoenr4/rules/rules.json'
savedRulesPath = '/root/workspace/challenge_yara_guidoenr4/rules/saved_rules.yara'
workspacePath = '/root/workspace/challenge_yara_guidoenr4'

# --------------------------------------------------LOGGIN- AUTHENTICATION ------------------------#

users = {
    'admin': generate_password_hash('root'),
    'guido': generate_password_hash('mercadolibre')
}


@auth.verify_password
def verify_password(username, password):
    if username in users and \
            check_password_hash(users.get(username), password):
        return username


# -------------------------------------------------- GET -----------------------------------------#
@app.route('/')
def host():
    return "Hello, Friend :) Bienvenido al meli-challenge de Guido Enrique", 200


@app.route('/rules', methods=['GET'])
@auth.login_required()
def getRules():
    if theFileIsEmpty(rulesPath):
        return jsonify({'error': 'no rules ;D'}), 404
    else:
        with open(rulesPath) as json_file:
            data = json.load(json_file)
            return jsonify(data), 200


@app.route('/rules/<string:rule_name>', methods=['GET'])
@auth.login_required()
def getRule(rule_name):
    with open(rulesPath, 'r') as ruleslist:
        data = json.load(ruleslist)
    rulesFound = [rule for rule in data if rule['name'] == rule_name]
    if len(rulesFound) > 0:
        return jsonify({'rule': rulesFound[0]}), 200
    else:
        return jsonify({'message': "Rule not found"}), 404


# ------------------------------------------------- POST ------------------------------------------#
@app.route('/api/rule', methods=['POST'])
@auth.login_required()
def addRule():
    try:
        name = request.json['name']
        rule = request.json['rule']
    except KeyError:
        return jsonify({'status': str(KeyError)}), 409
    else:
        return addRuleToTheFile(name, rule)


@app.route('/api/analyze/text', methods=['POST'])
def analyzeText():
    try:
        text = request.json['text']
        rulesIds = request.json['rules']
    except KeyError:
        return jsonify({'status:': str(KeyError)}), 409
    else:
        checkRules()
        return theTextPassTheRules(text, rulesIds)


ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif'}


@app.route('/api/analyze/file', methods=['POST'])
def analyzeFile():
    try:
        contentType = request.headers['content-type']
        rulesIds = ast.literal_eval('[' + request.form['rules'] + ']')  # converting to list
        file = request.files['file']
        extension = file.filename.split('.')
        ALLOWED_EXTENSIONS.__contains__(extension[1])
    except KeyError as e:
        return jsonify({'status:': str(KeyError)}), type(e).__name__, 409
    else:
        checkRules()
        return theFilePassTheRules(file, rulesIds)

# --------------------------------------------------TOOLS-------------------------------------------#

def checkRules():
    if theFileIsEmpty(savedRulesPath):
        return jsonify({'status:': 'there are no rules '}), 404

def generateNewRule(id, name, rule):
    return {"name": name, "rule": rule, "id": id}


def theFileIsEmpty(filepath):
    return os.stat(filepath).st_size == 0


def addRuleToTheFile(name, rule):
    if theFileIsEmpty(rulesPath):
        new_rule = generateNewRule(0, name, rule)
        with open(rulesPath, "r+") as file:
            data = [new_rule]
            json.dump(data, file, indent=3)
            return jsonify(new_rule), 201
    else:
        if theRuleExist(name):
            return jsonify({"error": "the rule already exist"})
        else:
            new_rule = generateNewRule(generateNewId(), name, rule)
            file = open(rulesPath, "r")
            data = json.load(file)
            file.close()
            data.append(new_rule)
            with open(rulesPath, 'w') as writefile:
                json.dump(data, writefile, indent=3)
            print(Bcolors.CGREEN + '[INFO]: New rule -> ' + name + ' added succesfuly' + Bcolors.ENDC)
            rules = loadCurrentRules()
            return jsonify(new_rule), 201


def generateNewId():
    with open(rulesPath) as rulesfile:
        data = json.load(rulesfile)
        return len(data)


def theRuleExist(rulename):
    if theFileIsEmpty(rulesPath):
        return False
    else:
        with open(rulesPath) as currentRules:
            data = json.load(currentRules)
            for rule in data:
                if rulename == rule["name"]:
                    return True
            return False


def loadCurrentRules():
    if theFileIsEmpty(rulesPath):
        print(Bcolors.WARNING + "[WARNING]: There are no rules in rules.json" + Bcolors.ENDC)
    else:
        with open(rulesPath, "r") as currentRules:
            data = json.load(currentRules)
        with open(savedRulesPath, 'a+') as savedrules:
            savedrules.truncate(0)
            for rule in data:
                savedrules.write(rule["rule"] + '\n\n')
        print(Bcolors.OKGREEN + '[INFO]: ' + str(len(data)) + ' rules compiled succesfuly' + Bcolors.ENDC)
        return compileCurrentRules()


def findRuleById(id):
    with open(rulesPath) as json_rules:
        data = json.load(json_rules)
    for element in data:
        if id == element["id"]:
            return element["name"].title().replace(' ', '')
    return None


def compileCurrentRules():
    return yara.compile(filepath=savedRulesPath)


def matchResult(id, matches):
    rule = findRuleById(id)
    if rule is None:
        return {"matched": "error", "cause": "the rule " + str(id) + " doesnt exist", "rule_id": id}
    else:
        if matches.__contains__(rule):
            return {"rule_id": id, "matched": True}
        else:
            return {"rule_id": id, "matched": False}


def matchResults(rulesids, matches):
    results = {'status': 'ok', 'results': []}
    for id in rulesids:
        results['results'].append(matchResult(id, matches))
    return json.dumps(results, indent = 4)


def toStr(matchrules):
    return list(map(lambda x: str(x), matchrules))


def generateRulesToMatch(rulesids):
    rulesToMatch = []
    for id in rulesids:
        rulesToMatch.append(findRuleById(id))
    return rulesToMatch


def theTextPassTheRules(text, ruleslist):
    if theFileIsEmpty(savedRulesPath):
        return jsonify({'status': 'there are no rules'}), 404
    else:
        path = os.getcwd() + '/text.txt'
        with open(path, 'w') as textf:
            textf.write(text)
        with open(path, 'rb') as file:
            matches = toStr(rules.match(data=file.read()))
        os.remove(path)
        rulesids = []
        for rule in ruleslist:
            rulesids.append(rule['rule_id'])
        return matchResults(rulesids, matches), 200


def theFilePassTheRules(file, rulesids):
    if theFileIsEmpty(savedRulesPath):
        return json.dumps({'status': 'there are no rules'}, indent = 4), 404
    else:
        matches = toStr(rules.match(data=file.read()))
        return matchResults(rulesids, matches), 200


rules = loadCurrentRules()
if __name__ == '__main__':
    os.chdir('/root/workspace/challenge_yara_guidoenr4')
    app.run(debug=False, port=8080, host="0.0.0.0")
