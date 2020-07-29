
import yara
import json
from flask import Flask, jsonify, request
from rules import rulesList # lista de rules

app = Flask(__name__) # uso flas para levantar el sv

if __name__ == '__main__':
    app.run(debug=True, port=4000)

#--------------------------------------------------GET ------------------------------------------#

@app.route('/')
def host(): #retorna un mensaje json para verificar que el sv anda
    return jsonify({"message": "guidoenr4 yara_challenge - meli"})

@app.route('/rules', methods=['GET']) # retorna todas las rules que hay en el server
def getRules():
    return jsonify(rulesList)

@app.route('/rules/<string:rule_name>', methods=['GET']) # retorna una rule especifica, si no esta, retorna un message
def getRule(rule_name):
    rulesFound = [rule for rule in rulesList if rule['name'] == rule_name] #barrido a la lista para ver la rule que piden
    if len(rulesFound) > 0:
        return jsonify({"rule": rulesFound[0]}) # retorno la rule encontrada
    else:
        return jsonify({"message":"Rule not found"})

#--------------------------------------------------POST-------------------------------------------#
@app.route('/api/rule', methods = ['POST'])
def addRule():
    new_rule = { # creo la rule con formato json y con el request.json['algo'] obtengo el value en ese campo mediante una request
        "name": request.json['name'], # se obtiene de una peticion post al server, no por parametro, por eso el request.json
        "rule": request.json['rule']
    }
    id = len(rulesList) + 1
    if rulesList.append(new_rule):
        return jsonify({"id":id, "name":new_rule['name'],"rule":new_rule['rule'],"response_code":201})
    else:
        return jsonify({"errorStatus":rulesList.append(new_rule)})

@app.route('/api/analyze/text', methods = ['POST'])
def addTextToAnalize():
    new_text_to_analize = {
        "text": request.json['text'],
        "rules": request.json['rules']
    }


