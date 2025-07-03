# Stage 1: Build the Next.js app
FROM node:18-alpine AS builder

# Set working directory
WORKDIR /app

# Copy package files and install dependencies
COPY package*.json ./
RUN npm install

# Copy the rest of the application code
COPY . .

# Add environment variables
ARG NEXT_PUBLIC_CA_URL
ENV NEXT_PUBLIC_CA_URL=$NEXT_PUBLIC_CA_URL

# Build the Next.js app
RUN npm run build

# Create running image
FROM node:18-alpine

# Create app directory
WORKDIR /app

# Copy built app and production dependencies
COPY --from=builder /app/package*.json ./
COPY --from=builder /app/.next ./.next
COPY --from=builder /app/public ./public
COPY --from=builder /app/node_modules ./node_modules
COPY --from=builder /app/next.config.mjs ./

# Expose the port Next.js will run on
ARG UI_PORT
EXPOSE $UI_PORT

# Start the application
CMD ["npm", "start"]
