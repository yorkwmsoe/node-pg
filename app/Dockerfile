FROM node

EXPOSE 3000

WORKDIR /app

ENV PGUSER=root
ENV PGPASSWORD=mySecretPassword
ENV PGHOST=host.docker.internal
ENV PGPORT=5432
ENV PGDATABASE=test

ENV VAULT_USERNAME=root
ENV VAULT_PASSWORD=mySecretPassword

COPY . .
RUN npm install
ENTRYPOINT  ["node", "index.js"]