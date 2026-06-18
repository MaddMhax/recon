# Build context is the project root (see docker-compose.yml)
FROM node:20-alpine

WORKDIR /usr/src/app

# Install dependencies first to leverage Docker layer caching
COPY backend/package*.json ./
RUN npm install --omit=dev

# Copy application source and the static frontend
COPY backend/src ./src
COPY frontend ./frontend

ENV NODE_ENV=production
EXPOSE 3000

# Run as the unprivileged user shipped with the node image
USER node

CMD ["node", "src/server.js"]
