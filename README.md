# Resolucion (yara-api challenge mercadolibre guidoenr4) 

Implemente una **[API-REST](https://es.wikipedia.org/wiki/Transferencia_de_Estado_Representacional)** usando **Python3.8** con **Pycharm IDE** de Jetbrains.
La api funciona a costas de **[Flask](https://flask.palletsprojects.com/en/1.1.x/)** un framework escrito en python que permite crear un backend para un website para poder recibir y manipular requests.
El script levanta un server en el `http://localhost:8080` de quien lo ejecute. La finalidad de este website es poder subir reglas de Yara, verlas mediante una peticion `GET`, poder mandar peticiones `POST` para hacer varias cosas, tales como analizar un archivo, analizar un texto, o hasta incluso añadir una nueva regla de yara.
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
La funcion `addRule()` *line: 37 on main.py* al recibir una regla, si se puede agregar, la agrega y la compila en el momento para que ya quede lista para usar.


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
   
Pero en el caso en el que **las reglas no se encuentren cargadas**, la pagina no retorna un error, sino otro ResponseBody diciendo que esa regla no existe, para darle a conocer al usuario que el error se debe a un error de tipeo. Un ResponseBody podria ser el siguiente:

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
Se agrego una **funcionalidad** para este caso, que consta de tener una lista con un tipo de archivos permitidos, lo cual esta pensado para que al recibir archivos dudosos del tipo `.exe`, `.py`, entre otros, el sitio responda con un codigo de error y no permita subir el archivo para analizarlo, porque podria by-passear las rules. 
```json
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif'}
```
Curl de ejemplo:

    curl -X POST \
      http://localhost:8080/api/analyze/file \
      -H 'content-type: multipart/form-data; boundary=----WebKitFormBoundary7MA4YWxkTrZu0gW' \
      -F file='@/root/Escritorio/default_file.txt' \
      -F 'rules=1,2'


La funcion `analyzeFile()` *line: 69 on main.py* al recibir un file, tiene la misma logica que la funcion `analyzeText()` y los mismos ResponseBody, la unica diferencia en esta funcion es que en su implementacion de `try:catch:else` tambien chequea que se les pasen datos del form, headers y el archivo en cuestion, tambien verificando lo mencionado arriba sobre las extensiones. \
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

Implemente [Docker](https://www.docker.com/) para que la API-REST pueda ser corrida en cualquier sistema operativo. Cree una [imagen de docker](https://hub.docker.com/repository/docker/guidoenr4/yara-python-3.8) que contiene **python3.8** y algunas librerias de python (como yara) que son necesarias para correr este código.

**Dockerfile:**
```python
FROM guidoenr4/yara-python-3.8:latest

WORKDIR /home

COPY . .

RUN pip3 install Flask-HTTPAuth \
&& pip3 install -r requirements.txt

ENTRYPOINT ["python3","main.py"]
```
## Pasos

#### 1: Docker
Instalar [Docker](https://www.docker.com/)

#### 2: Descargar el repositorio
Descargar el repositorio mediante un \
 `git clone https://github.com/irt-mercadolibre/challenge_yara_guidoenr4` \
  o simplemente descargar el `.zip` y extraerlo

#### 3: Compilar el proyecto mediante docker
Una vez instalado docker y clonado el repositorio, correr el comando: \
`docker build -t melichallenge .` \
dentro del directorio donde fue descargado el repositorio (`cd challenge_yara_guidoenr4`), para poder compilarlo y descargar las imagenes y librerias necesarias automaticamente.

#### 4: Correr el proyecto
Al estar compilado se puede correr de varias formas, la que yo recomiendo es correrla con el comando: \
 `docker run -d -p 8080:8080 --name melitest melichallenge` \
donde la aplicación corre de fondo, lo cual en este caso es util puesto que es un servidor y queremos tenerlo levantado para hacer las correspondientes pruebas. \
el `PUERTOLOCAL=8080` es un puerto aleatorio que debe elegir el cliente para poder hacer el mapeo de puertos (primer parametro), y el `8080` es el default del script. \
**recomiendo usar el puerto 8080** para poder acceder desde su navegador a `localhost:8080` y ademas , poder correr los tests que envian peticiones a ese puerto


#### 5: Ver las respuestas del servidor
Para poder ver en tiempo real las respuestas del servidor, se debe ejecutar el comando \
`docker logs -f melitest` \
lo cual permite ver el historial de peticiones que le son enviadas al servidor, donde el mismo esta corriendo de fondo \
Al estar iniciado el servidor, podes entrar a `http://localhost:8080` desde tu navegador y recibir una respuesta como esta:
```json
Hello, Friend :) Bienvenido al meli-challenge de Guido Enrique
```
para verificar que el servidor esta corriendo y funcionando.. \
Luego de un tiempo determinado, podes finalizar el servidor con el comando \
`docker stop melitest` \
y liberar la conexion en el puerto 8080 \
**OBS:** **al stopear el servidor, el mismo perdera todas las reglas que ya tiene cargadas, y quedara unicamente con su defaultRule**

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
## TESTING - Python Unit Tests
.\
.\
.\
.\
.\
.


## Scripts en BASH (only on linux)
**El repositorio cuenta con 3 carpetas: `addRules/` , `analyzeFiles` y `analyzeTexts` que contienen scripts escritos en **bash** para realizar pruebas de una manera mas rapida**  
#### Añadir una nueva regla yara
Implemente algunas reglas de yara que se pueden ver en el directorio del repositorio **addRules** el cual contiene varias reglas de yara ya cargadas en un curl para un manejo mas facil en el envio de peticiones al servidor. Tambien con el parametro `curl -u admin:root` para poder autenticarse \
`acces toke rule`, `suspicious strings rule`, `acces_token_del_31enero2016` , `es_exploit` , son algunas de ellas.\
ejemplo: 

**`bash addRules/suspicious_strings.sh`**
```console
#!bin/sh

echo -e "\e[92m Add rule : SuspiciosStrings"
curl --request POST \
     --url http://localhost:8080/api/rule \
     --header 'content-type: application/json' \
     --data '{
      "name":"suspicios strings rule",
      "rule":"rule Misc_Suspicious_Strings\r\n{\r\n strings:\r\n $a0 = \"backdoor\"\r\n $a1 = \"virus\"\r\n condition:\r\n   any of them\r\n}"
      }' \
     -u admin:root
```

**`bash addRules/acces_token.sh`**

```console
#!bin/sh

echo -e "\e[92m Add rule : is a acces token"
curl --request POST \
     --url http://localhost:8080/api/rule \
     --header 'content-type: application/json' \
     --data '{
       "name":"access token rule",
       "rule":"rule AccesToken\r\n{\r\n strings:\r\n $a0 = \"TOKEN_\"\r\n $a1 = \"TOKEN\"\r\n condition:\r\n   any of them\r\n}"
       }' \
    -u admin:root
```       
**`bash addRules/acces_token_del_31enero2016.sh`**
```console
#!bin/sh

echo -e "\e[92m Add rule : el token se creo despues del 31 de enero de 2016"
curl --request POST \
     --url http://localhost:8080/api/rule \
     --header 'content-type: application/json' \
     --data '{
      "name":"old token rule",
      "rule":"rule oldToken\r\n{\r\n strings:\r\n $a0 = \"2016-02\"\r\n $a1 = \"2016-01-31\"\r\n $a1 = \"2017-\"\r\n $a2 = \"2018-\"\r\n $a3 = \"2019-\"\r\n $a4 = \"2020-\"\r\n condition:\r\n   any of them\r\n}"
      }' \
  -u admin:root
```       
#### Analizar un texto
Tambien existe el directorio **analyzeTexts** que contiene scripts pero para analizar los textos.
ejemplo:
**`bash analyzeTexts/analyze_token.sh`**
```console
  #!/bin/bash
  echo -e "\e[93m Analyze text : defaultext"

  curl --request POST \
    --url http://localhost:8080/api/analyze/text \
    --header 'content-type: application/json' \
    --data '{
     "text":"TOKEN_2014-06-03_112332",
     "rules": [
        {
           "rule_id": 0
        },
        {
           "rule_id": 1
        }
     ]
  }'
```
#### Analizar un archivo
En el directorio **analyzeFiles** se encuentran scripts para analizar un file donde se le debe pasar el path del archivo a mandar, obviamente el mismo tiene que estar **creado** \
ejemplo:
**`bash analyzeTexts/defaultFile.sh`**
```console
  #!bin/sh

  echo -e "\e[93m Analyze file: /root/Escritorio/default_file.txt"

  curl -X POST \
    http://localhost:8080/api/analyze/file \
    -H 'content-type: multipart/form-data; boundary=----WebKitFormBoundary7MA4YWxkTrZu0gW' \
    -F file='@/root/Escritorio/default_file.txt' \
    -F 'rules=1,2'
```

