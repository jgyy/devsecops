# DEMO ONLY — pinned to a deliberately outdated base image to seed known
# OS-level HIGH/CRITICAL CVEs for this repo's container image scanning gate.
# This is a distinct vulnerability class from the npm-lockfile CVEs the SCA
# gate already catches: these live in the base image's OS packages
# (openssl, curl, etc.), not in anything sample-app's own code depends on.
FROM node:22.0.0

WORKDIR /app

COPY package*.json ./
RUN npm install

COPY tsconfig.json ./
COPY src ./src
COPY data ./data
RUN npm run build

EXPOSE 3000

CMD ["node", "dist/index.js"]
