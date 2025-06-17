FROM node:20-slim

WORKDIR /app

COPY package*.json ./

# Instalar solo lo necesario y en una sola capa
RUN apt update && apt upgrade && apt install -y curl \
  && npm install --omit=dev \
  && apt clean \
  && rm -rf /var/lib/apt/lists/*

COPY . .

EXPOSE 3000

CMD ["node", "index.js"]
