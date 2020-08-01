# Resolucion (yara-api challenge mercadolibre guidoenr4) 

Implemente una **[API-REST](https://es.wikipedia.org/wiki/Transferencia_de_Estado_Representacional)** usando **Python3.8** con **Pycharm IDE** de Jetbrains.
La api funciona a costas de **[Flask](https://flask.palletsprojects.com/en/1.1.x/)** un framework escrito en python que permite crear un backend para un website para poder recibir y manipular requests.
El script levanta un server en el `localhost:0.0.0.0:8080` de quien lo ejecute. La finalidad de este website es poder subir reglas de Yara, verlas mediante una peticion `GET`, poder mandar peticiones `POST` para hacer varias cosas, tales como analizar un archivo, analizar un texto, o hasta incluso añadir una nueva regla de yara.
Cuenta con las siguientes rutas de acceso:

## Method: GET
**Index** \
`localhost:0.0.0.0/` 

**Reglas de Yara actualmente cargadas en la page** (necesita autenticación) \
`localhost:0.0.0.0/rules` 

**Regla especificandola por su nombre:**`rulename` \
`localhost:0.0.0.0/rules/rulename` 

## Method: POST

#### Add Rule 
`localhost:0.0.0.0/api/rule` \
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
`localhost:0.0.0.0/api/analyze/text` \
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
   
pero en el caso en el que **las reglas no se encuentren cargadas**, la pagina no retorna un error, sino otro ResponseBody diciendo que esa regla no existe, para darle a conocer al usuario que el error se debe a un error de tipeo. Un ResponseBody podria ser el siguiente:

    {
    "status": "ok",
    "results": [
      {
        "cause": the rule 1 doesnt exist,
        "status": error
      },
      {
        "rule_id": 0,
        "matched": true
      }
    ]
    }

#### Analyze File
`localhost:0.0.0.0/api/analyze/file` \
Mediante esta ruta se puede mandar una peticion `POST` con un archivo para analizar, especificandole que reglas se quieren matchear con el archivo. No necesita autenticación, cualquier cliente podria mandar un archivo y verificar si el archivo pasa por las rules cargadas actualmente \
Curl de ejemplo:

    curl -X POST \
      http://localhost:8080/api/analyze/file \
      -H 'content-type: multipart/form-data; boundary=----WebKitFormBoundary7MA4YWxkTrZu0gW' \
      -F file=@file \
      -F 'rules=1,2'


La funcion `analyzeFile()` *line: 69 on main.py* al recibir un file, tiene la misma logica que la funcion `analyzeText()` y los mismos ResponseBody, la unica diferencia en esta funcion es que en su implementacion de `try:catch:else` tambien chequea que se les pasen datos del form y de los headers.

        try:
          contentType = request.headers['content-type']
          rules = ast.literal_eval('[' + request.form['rules'] + ']') 
          file = request.form['file']

# Instalación

Implemente [Docker](https://www.docker.com/) para que la API-REST pueda ser corrida en cualquier sistema operativo. Cree una [imagen de docker](https://hub.docker.com/repository/docker/guidoenr4/yara-python-3.8) que contiene python3.8 y algunas librerias de python (como yara) que son necesarias para correr este código.

Dockerfile:

    FROM guidoenr4/yara-python-3.8:latest

    WORKDIR /home

    COPY . .

    RUN pip3 install Flask-HTTPAuth \
    && pip3 install -r requirements.txt

    ENTRYPOINT ["python3","main.py"]

## Pasos

#### 1
Instalar [Docker](https://www.docker.com/)

#### 2
Descargar el repositorio mediante un `git clone https://github.com/irt-mercadolibre/challenge_yara_guidoenr4` o simplemente descargar el `.zip` y extraerlo

#### 3
Una vez instalado docker y clonado el repositorio, correr el comando : `docker build -t melichallenge .` dentro del directorio donde fue descargado el repositorio, para poder compilarlo y descargar las imagenes y librerias necesarias automaticamente.

#### 4
Al estar compilado se puede correr de varias formas, la que yo recomiendo es correrla con el comando `docker run -d -p PUERTOLOCAL:8080 melichallenge `
donde la aplicación corre de fondo, lo cual en este caso es util puesto que es un servidor y queremos tenerlo levantado para hacer las correspondientes pruebas.
el `PUERTOLOCAL` es un puerto aleatorio que debe elegir el cliente para poder hacer el mapeo de puertos, y el `8080` es el default del script.
*recomiendo usar -p 8080:8080* para poder acceder desde su navegador a `localhost:8080`

#### 5
Para poder ver en tiempo real las respuestas del servidor, se debe ejecutar el comando `docker logs -f melichallenge`, al hacer un `CTRL+C` matarias el log, pero **no** el servidor.
