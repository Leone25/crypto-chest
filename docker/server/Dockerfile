FROM node:latest

ENV DEVELOPMENT=${DEVELOPMENT}

# Working directory
WORKDIR /usr/src/app

# Copy package.json and package-lock.json
COPY package*.json ./
COPY server/package*.json ./server/

# Install dependencies
RUN npm install

# Copy source code
COPY . .

# Expose ports
EXPOSE 3000

# Run the server
CMD if [ "$DEVELOPMENT" = "true" ]; \
	then npm run dev; \
else \
	npm run start; \
fi