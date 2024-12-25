FROM postgres:16.3

ENV POSTGRES_USER postgres
ENV POSTGRES_PASSWORD password
ENV POSTGRES_DB cryptochest
ADD ./docker/database/createTables.sql /docker-entrypoint-initdb.d/