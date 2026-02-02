FROM node:20-slim

# Puppeteer 의존성 설치
RUN apt-get update && apt-get install -y \
    chromium \
    fonts-ipafont-gothic fonts-wqy-zenhei fonts-thai-tlwg fonts-kacst fonts-freefont-ttf \
    --no-install-recommends \
    && rm -rf /var/lib/apt/lists/*

# Puppeteer 환경변수
ENV PUPPETEER_SKIP_CHROMIUM_DOWNLOAD=true
ENV PUPPETEER_EXECUTABLE_PATH=/usr/bin/chromium

WORKDIR /app

# package.json 복사 및 설치
COPY package*.json ./
RUN npm install

# 소스 복사
COPY . .

EXPOSE 3000

CMD ["node", "server.js"]
