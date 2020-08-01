FROM guidoenr4/yara-python-3.8:latest

WORKDIR /home

COPY . .

RUN pip3 install Flask-HTTPAuth \
    && pip3 install -r requirements.txt

ENTRYPOINT ["python3","main.py"]