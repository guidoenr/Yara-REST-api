#@autor : github.com/guidoenr4

import yara,os,json,sys
from flask import Flask, jsonify, request
from rules import rulesList # lista de rules en rules.py
from flask import Response


app = Flask(__name__) # uso flas para levantar el sv

#--------------------------------------------------GET ------------------------------------------#
@app.route('/')
def host(): #retorna un mensaje json para verificar que el sv anda
    return jsonify({'message': "guidoenr4 yara_challenge - meli"})

@app.route('/rules', methods=['GET']) # retorna todas las rules que hay en el server
def getRules():
    return jsonify(rulesList)

@app.route('/rules/<string:rule_name>', methods=['GET']) # retorna una rule especifica, si no esta, retorna un message
def getRule(rule_name):
    rulesFound = [rule for rule in rulesList if rule['name'] == rule_name] #barrido a la lista para ver la rule que piden
    if len(rulesFound) > 0:
        return jsonify({'rule': rulesFound[0]}) # retorno la rule encontrada
    else:
        return jsonify({'message':"Rule not found"})

#--------------------------------------------------POST-------------------------------------------#
@app.route('/api/rule', methods = ['POST'])
def addRule(): # se borran cuando el server se reinicia
    try:
        name = request.json['name']
        rule = request.json['rule']
    except KeyError as e:
        return jsonify({'status': str(KeyError)}), type(e).__name__
    else:
        id = len(rulesList)
        new_rule={
            'name':name,
            'rule':rule,
            'id':id
        }
        rulesList.append(new_rule)
        compileRule(new_rule['rule'])
        return jsonify({'id': id, 'name': new_rule['name'], 'rule': new_rule['rule']}), 201

@app.route('/api/analyze/text', methods = ['POST'])
def analyzeText():
   responseBody={
       'status':'ok',
       'results':[
       ]
   }
   try:
       text = request.json['text']
       rules = request.json['rules']
   except KeyError as e:
       return jsonify({'status:': str(KeyError)}), type(e).__name__

   for rule in rules:
       responseBody['results'].append(theTextPassTheRule(text, rule['rule_id']))
   return responseBody,200

@app.route('/api/analyze/file', methods = ['POST'])
def analyzeFile():
    pass


#--------------------------------------------------TOOLS-------------------------------------------#
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
    i=0
    for rule in rulesList:
        rule = rulesList[i]
        if rule['id'] == id:
            return rule['rule']
        i+=1

def compileCurrentRules():
    for element in rulesList:
        try:
            compileRule(element['rule'])
        except:
            print("error compiling the rules")

def theTextPassTheRule(text, rule_id):
    rule = findRuleById(rule_id)
    if (rule == None):
        return {'status':'error','cause':'the rule '+str(rule_id) + ' doesnt exist'}
    rules = yara.compile(source=rule)
    filepath = text + '.txt'
    f = open(filepath, 'w') #yara si o si te obliga a hacer un file, no lo podes hacer con un string de python
    f.write(text)
    f.close()
    match = rules.match(filepath)
    x = len(match) > 0
    os.remove(filepath)
    return {'rule_id': rule_id, 'matched':x}


if __name__ == '__main__':
    compileCurrentRules()
    loadCurrentRules()
    app.run(debug=True, port=4000)









