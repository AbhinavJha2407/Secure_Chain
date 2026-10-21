FROM node:22-alpine
WORKDIR /app
COPY package*.json ./
RUN npm ci --omit=dev
COPY . .
RUN mkdir -p src/db /app/data
EXPOSE 4000
CMD ["node", "src/server.js"]
