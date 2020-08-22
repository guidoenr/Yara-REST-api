# challenge_yara_guidoenr4 (res)

Implemente una **[API-REST](https://es.wikipedia.org/wiki/Transferencia_de_Estado_Representacional)** usando **Python3.8**.
La api funciona a costas de **[Flask](https://flask.palletsprojects.com/en/1.1.x/)** un framework escrito en python que permite crear la estructura de un backend para poder manipular requests, entre otras cosas.
La finalidad de este website es poder interactuar con el sitio en tiempo real, realizando varias peticiones al mismo. Cuenta con varias funcionalidades, tales como analizar un archivo, analizar un texto, añadir una regla de yara, entre otras cosas.

**OBS**: **Version 2**\
Existe otra version la cual es mas dinamica a comparación de esta, donde las reglas de yara que son añadidas en el momento se borran una vez que el servidor es finalizado. 
Les presento esta que tal vez cumple mas con los requerimientos del enunciado.
> 'Es importante que como esta API va a tener bastante trafico, no tenga que cargar las reglas cada vez que tenga que hacer un análisis'

# Documentación

Cuenta con las siguientes rutas de acceso:

## Method: GET
**Index** \
`http://localhost:8080` 

**Reglas de Yara actualmente cargadas en la page** (necesita autenticación) \
`http://localhost:8080/rules` 

**Regla especificandola por su nombre:** *ej: defaultRule* \
`http://localhost:8080/rules/rulename` 

## Method: POST

#### Add Rule 
`http://localhost:8080/api/rule` \
Para poder añadir una regla de yara, se necesita una autenticacion especial, no cualquier cliente puede subir una regla .
Curl de ejemplo:
   
    curl --request POST \
      --url http://localhost:8080/api/rule \
      --header 'content-type: application/json' \
      --data '{
      "name":"esto no es coca papi rule",
      "rule":"rule EstoNoEsCocaPapiRule\r\n{\r\n strings:\r\n $my_text_string = \"esto no es coca papi\"\r\n condition:\r\n   $my_text_string\r\n}"
      }' \
      -u user:password
Donde el **user:password** es el usuario y contraseña (información en la seccion de autenticación).
La funcion `addRule()` *line: 37 on main.py* al recibir una regla, si se puede agregar, la agrega y la compila en el momento para que ya quede lista para usar. \
Agregue una funcionalidad en esta funcion: al querer agregar una regla que ya existe, la misma no se agregara y retornara status code : **`409 Conflict`** \
El formato para las reglas debe ser el siguiente: \
**`name: una nueva regla`** \
**`rule: rule UnaNuevaReglaRule[..]`**


#### Analyze Text
`http://localhost:8080/api/analyze/text` \
Mediante esta ruta se puede mandar una peticion `POST` con un texto para analizar, especificandole que reglas se quieren matchear con el texto. No necesita autenticación, cualquier cliente podria mandar un texto y verificar si el texto pasa por las rules cargadas actualmente \
Curl de ejemplo:   

    curl --request POST \
      --url http://localhost:8080/api/analyze/text \
      --header 'content-type: application/json' \
      --data '{
      “text”: ”estoesuntextoaanalizar”,
      "rules": [
        {
          "rule_id": 1
        },
        {
          "rule_id": 2
        }
      ]
    

La funcion `analyzeText()` *line: 56 on main.py* al recibir un texto, hace un barrido con las reglas que le son pasadas por parametros y las aplica al texto tambien pasado por parametro, en caso de que **las reglas se encuentren cargadas** un ResponseBody podria ser el siguiente:

    {
    "status": "ok",
    "results": [
      {
        "rule_id": 1,
        "matched": true
      },
      {
        "rule_id": 2,
        "matched": false
      }
    ]
    }
   
Pero en el caso en el que **las reglas no se encuentren cargadas**, la pagina no retorna un error, sino otro ResponseBody diciendo que esa regla no existe, para darle a conocer al usuario que el error se debe a un error de tipeo, porque no merece la pena retornar solamente un codigo de error cuando el texto a analizar pudo ser matcheado con alguna rule. Un ResponseBody podria ser el siguiente:

    {
    "status": "ok",
    "results": [
      {
        "rule_id": 42,
        "matched": error,
        "cause": the rule 42 doesnt exist
      },
      {
        "rule_id": 0,
        "matched": true
      }
    ]
    }

#### Analyze File
`http://localhost:8080/api/analyze/file` \
Mediante esta ruta se puede mandar una peticion `POST` con un archivo para analizar, especificandole que reglas se quieren matchear con el archivo. No necesita autenticación, cualquier cliente podria mandar un archivo y verificar si el archivo pasa por las rules cargadas actualmente. \
Se agrego una **funcionalidad** para este caso, que consta de tener una lista con un tipo de archivos permitidos, lo cual esta pensado para que al recibir archivos dudosos del tipo `.exe`, `.py`, entre otros, el sitio responda con un codigo de error y no permita subir el archivo para analizarlo, porque podria by-passear las rules. Aunque tambien podria hacerse una regla de yara para verificar su extension, o el filesize, entre otras cosas.. me parecio una buena medida de seguridad que el mismo no sea aceptado directamente para analizar. 
```json
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif'}
```
Curl de ejemplo:

    curl -X POST \
      http://localhost:8080/api/analyze/file \
      -H 'content-type: multipart/form-data; boundary=----WebKitFormBoundary7MA4YWxkTrZu0gW' \
      -F file='@/root/Escritorio/default_file.txt' \
      -F 'rules=1,2'


La funcion `analyzeFile()` *line: 69 on main.py* al recibir un file, tiene la misma logica que la funcion `analyzeText()` y los mismos ResponseBody, la unica diferencia en esta funcion es que en su implementacion de `try:except:else` tambien chequea que se les pasen datos del form, headers y el archivo en cuestion, tambien verificando lo mencionado arriba sobre las extensiones. \
*`line 78 on main.py`*
```python
try:
    contentType = request.headers['content-type']
    rules = ast.literal_eval('[' + request.form['rules'] + ']')
    file = request.files['file']
    extension = file.filename.split('.')
    ALLOWED_EXTENSIONS.__contains__(extension[1])
```

# Instalación

Implemente [Docker](https://www.docker.com/) para que la API-REST pueda ser ejecutada en cualquier sistema operativo. Cree una [imagen de docker](https://hub.docker.com/repository/docker/guidoenr4/yara-python-3.8) que contiene **python3.8** y algunas librerias de python (como yara) que son necesarias para correr este código.

**Dockerfile:**
```python
FROM guidoenr4/yara-python-3.8:latest

WORKDIR /root/workspace/challenge_yara_guidoenr4/

COPY . .

RUN pip3 install Flask-HTTPAuth \
    && pip3 install -r requirements.txt

ENTRYPOINT ["python3","main.py"]
```
## Pasos
*Las opciones marcadas con :star: son las recomendadas*

1. **Instalar [Docker](https://www.docker.com/) (guia disponible en el website oficial)**

2.  **Descargar el repositorio**
    - **`git clone https://github.com/irt-mercadolibre/challenge_yara_guidoenr4`** :star:
    - o simplemente descargar el `.zip` y extraerlo 
 
3. **Limpiar / Mantener las rules**
    - Si se quiere compilar el website sin rules, ejecutar el script: \
     **`bash bash-scripts/clean-rules.sh`** \
     que trunca los archivos que contiene las rules de yara ya existentes permitiendo que el mismo quede con 0 rules.
    - En caso de que se quiera mantener las rules, omitir este paso. :star:

4. **Compilar el proyecto (dentro del directorio del repositorio)**
    - **`docker build -t melichallenge .`** :star:
 
5. **Correr el proyecto**
   - Se puede correr de varias formas, **la forma que yo recomiendo** es utilizando el comando: \
    **`docker run -d -p 8080:8080 --name melitest melichallenge`** :star: \
    donde el servidor corre de fondo, lo cual en este caso es util puesto que queremos tenerlo levantado para hacer las correspondientes pruebas. 
   - En caso de no querer usar el puerto **8080** se debe realizar el mapeo de puertos correspondientes de la siguiente manera: \
   **`docker run -d -p PUERTO:8080 --name melitest melichallenge`** \
    donde el parametro `PUERTO` es un puerto que debe elegir el cliente para poder hacer el mapeo y luego acceder a ese puerto en lugar del  8080
          
6. **Ver las respuestas del servidor**
    - Mediante docker, al estar el servidor corriendo de fondo, se puede ejecutar el comando :\
    **`docker logs -f melitest`** :star:\
    para poder ver el historial de peticiones enviadas al servidor en tiempo real.
    - Tambien se puede acceder a **`http://localhost:8080`** y verlo en el navegador que quieras

7. **Verificar el funcionamiento**
    - Al estar iniciado el servidor, se puede acceder **`http://localhost:8080`** desde tu navegador y recibir una respuesta como esta:
```python
Hello, Friend :) Bienvenido al meli-challenge de Guido Enrique
```

**Detener el servidor** 
- Luego de un tiempo determinado, podes finalizar el servidor con el comando:\
    **`docker stop melitest`**\
    y liberar la conexion en el puerto 8080. Al detener el servidor, las reglas quedaran guardadas en **`rules/saved_rules.yara`** y al iniciar el servidor nuevamente las mismas se compilaran        
    






## Uso
Para el uso del servidor se pueden usar varios sitios webs que arman solicitudes get/post con un formato las legible, pero para un uso mas rapido.. recomiendo usar **curl** y/o los scripts en bash en la seccion de extras.
# Extras
## Logging - Autentication
Implemente una autenticacion para ciertas rutas del sitio, como `/rules` [METHOD=GET] , y para `api/rule` [METHOD=POST] utilizando la libreria [HTTPBasicAuth](https://flask-httpauth.readthedocs.io/en/latest/) de Flask\
Las credenciales de accesos son las siguientes: *(user:password)*
     
```json
 users = {
   'admin': 'root'
   'guido': 'mercadolibre'
  }
```

## Nuevas reglas de yara
El servidor viene iniciado con **5** reglas en  **`/rules/saved_rules.yara`**(reglas concretas para compilar) y **`/rules/rules.json`**(reglas para responder una peticion del usuario) 

**AccessTokenRule**: analiza un texto con el formato : `TOKEN_AAAA-MM-DD_IDUSUARIO` utilizando el motor de expresiones regulares de Yara.

```js
rule AccessTokenRule
{
  strings:
    $a0 = /TOKEN_([0-9]){4}-([0-9]){2}-([0-9]){2}_([0-9])+/ nocase wide ascii
  condition:
    $a0
}
```
**CreditCardRule**: analiza un texto con el formato de una tarjeta de credito, donde se asume que todas las tarjetas de creditos tienen **16 numeros** donde las mismas pueden venir con o sin separador.
>Ej: 1234-1234-1234-1234\
>Ej: 1234123412341234


```js
rule CreditCardRule
{
  strings:
    $a0 = /[0-9]{4}(-)?[0-9]{4}(-)?[0-9]{4}(-)?[0-9]{4}/
  condition: 
    $a0
}
```
**OldTokenRule**: analiza un texto con el mismo formato que la **AccessTokenRule** pero matcheando que el token haya sido creado despues del 31 de enero de 2016. 
```js
rule OldTokenRule
{
  strings:
    $a1 = /TOKEN_2016-(0([2-9]){1}|1(0-2){1})-([0-9]){2}_([0-9])+/ nocase wide ascii 
    $a2 = /TOKEN_(201([7-9]){1}|20([2-9]){1}([0-9]){1})-([0-9]){2}-([0-9]){2}_([0-9])+/ nocase wide ascii 
  condition:
    any of them
}
```

Las demas reglas que vienen cargadas son **SuspiciousStringsRule**, **EstoNoEsCocaPapiRule** y **DefaultRule** que no tienen nada en especial mas que una verificacion si existen **x** strings.
## Python Unit Tests
Hay varios tests en **`tests.py`** que prueban las funcionalidades del servidor, como añadir reglas, analizar textos, y demas.
Con un **86%** de lineas testeadas segun Coverage.\
Se pueden correr con :
- **`python3 tests.py`** (estando el servidor levantado)

Algunos ejemplos:


```python
def setUp(self):
    app.config['TESTING'] = True
    app.config['WTF_CSRF_ENABLED'] = False
    app.config['DEBUG'] = False
    self.app = app.test_client()

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

```

## Scripts en BASH (solo en linux)
**El repositorio cuenta con 3 carpetas en el directorio /bash-scripts: `addRules/` , `analyzeFiles/` y `analyzeTexts/` que contienen scripts escritos en **bash** para realizar pruebas de una manera mas rapida.**\
Pueden ser ejecutadas fuera del docker container, porque al fin y al cabo son peticiones a un servidor mediante curl.
Donde las peticiones se le hacen al **`localhost:8080`**

ejemplos:  
#### Añadir una nueva regla yara

**`bash addRules/suspicious_strings.sh`**\
**`bash addRules/access_token.sh`**\
**`bash addRules/access_token_del_31enero2016.sh`**
       
#### Analizar un texto
**`bash analyzeTexts/analyze_token.sh`**
#### Analizar un archivo
**`bash analyzeTexts/defaultFile.sh`**

------------------------------------------------------------------------------------------------------------------------------
## Observaciones
- Pense en guardar las rules en una base de datos, tal vez usando MongoDB o almacenandolas en el sitio.. pero tome la decision de guardar las rules en archivos `.json` para una simplicidad, creyendo que tal vez no se evalua este requerimiento en el enunciado. Ademas, permite cierta seguridad a ataques [IDORS](https://portswigger.net/web-security/access-control/idor).
- Los scripts estan hardcodeados con `rules_id` y `texts` al azar, los hice yo para probar el servidor.
En el caso de analisis de archivos hay un `file.txt` en el directorio `analyzeFiles/` con un texto al azar y en su mismo script esta hardcodeado su path en `file=@/root/workspace/challenge_yara_guidoenr4/analyzeFiles/file.txt`.
- El servidor cuenta con varias funcionalidades mas, tales como logs de ciertas cosas , que se pueden ver en el funcionamiento del mismo.
- La REST-API fue testeada en Kali-Linux y Windows7 sin errores.
- Existe una version 2, como mencione al principio, mas dinamica que esta.
- Para las respuestas en una terminal, se utiliza la funcion `json.dumps(indent=4)` para retornar los responseBody, lo cual permite un PrettyPrint, a diferencia de las peticiones hechas directamente desde el navegador, que usan la funcion `jsonify`. Esto quiere decir que si se hacen peticiones POST tales como **addRule** o **analyzeFile** en un sitio web alterno a la terminal, la respuesta del servidor, a pesar de ser correcta, no sera tan legible. 
- Los tests estan pensados con el status default del servidor, es posible que no corran si hay inconsistencias con los datos (ejemplo: borrar las rules del servidor y volver a cargarlas con otro orden, generando distintos IDS)

