FROM python:3.6

# Superset version
ARG SUPERSET_VERSION=0.29.0rc8

# Configure environment
ENV GUNICORN_BIND=0.0.0.0:8088 \
    GUNICORN_LIMIT_REQUEST_FIELD_SIZE=0 \
    GUNICORN_LIMIT_REQUEST_LINE=0 \
    GUNICORN_TIMEOUT=60 \
    GUNICORN_WORKERS=2 \
    LANG=C.UTF-8 \
    LC_ALL=C.UTF-8 \
    PYTHONPATH=/etc/superset:/home/superset:$PYTHONPATH \
    SUPERSET_REPO=apache/incubator-superset \
    SUPERSET_VERSION=${SUPERSET_VERSION} \
    SUPERSET_HOME=/var/lib/superset
ENV GUNICORN_CMD_ARGS="--workers ${GUNICORN_WORKERS} --timeout ${GUNICORN_TIMEOUT} --bind ${GUNICORN_BIND} --limit-request-line ${GUNICORN_LIMIT_REQUEST_LINE} --limit-request-field_size ${GUNICORN_LIMIT_REQUEST_FIELD_SIZE}"

RUN mkdir /home/superset

RUN useradd -U -m superset
RUN mkdir /etc/superset
RUN mkdir ${SUPERSET_HOME}
RUN chown -R superset:superset /etc/superset
RUN chown -R superset:superset ${SUPERSET_HOME}

RUN curl -sL https://deb.nodesource.com/setup_10.x | bash - && apt-get install -y nodejs

RUN apt-get update && apt-get install -y build-essential curl default-libmysqlclient-dev freetds-bin freetds-dev libffi-dev libldap2-dev libpq-dev libsasl2-2
RUN apt-get update && apt-get install -y libsasl2-dev libsasl2-modules-gssapi-mit libssl1.0
RUN apt-get clean
RUN rm -r /var/lib/apt/lists/*

WORKDIR /home/superset

RUN git clone https://github.com/ExentriqLtd/exentriq-advanced-analytics

WORKDIR /home/superset/exentriq-advanced-analytics

RUN pip install --no-cache-dir -r requirements.txt

RUN pip install --no-cache-dir flask-cors==3.0.3 flask-mail==0.9.1 flask-oauth==0.12 flask_oauthlib==0.9.5 gevent==1.2.2 impyla==0.14.0
RUN pip install --no-cache-dir infi.clickhouse-orm==1.0.2 mysqlclient==1.3.7 psycopg2==2.6.1 pyathena==1.5.1 pybigquery==0.4.10 pyhive==0.5.1
RUN pip install --no-cache-dir pyldap==2.4.28 pymssql==2.1.3 redis==2.10.5 sqlalchemy-clickhouse==0.1.5.post0 sqlalchemy-redshift==0.7.1 werkzeug==0.14.1

RUN cd superset/assets && npm ci && npm run build && rm -rf node_modules

COPY config/exentriq.py superset/exentriq.py
COPY config/config.py superset/config.py
COPY config/basic.html superset/templates/superset/basic.html
COPY config/init.html /usr/local/lib/python3.6/site-packages/flask_appbuilder/templates/appbuilder/init.html

RUN pip install .

COPY data/superset.db /var/lib/superset/superset.db
RUN chown -R superset:superset /var/lib/superset/superset.db

COPY superset /usr/local/bin

RUN chmod +x /usr/local/bin/superset-init

WORKDIR /home/superset

# Deploy application
EXPOSE 8088
HEALTHCHECK CMD ["curl", "-f", "http://localhost:8088/health"]
CMD ["gunicorn", "superset:app"]
USER superset
