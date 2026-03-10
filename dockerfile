FROM node:22-slim

WORKDIR /app

# Copy entire project
COPY . .

# Install dependencies
RUN npm install

ENV NODE_ENV=production
ENV PORT=3000
EXPOSE 3000

CMD ["npm", "start"]