FROM node:22-alpine AS build
WORKDIR /src
COPY package.json package-lock.json ./
RUN npm ci
COPY . .
ARG VITE_BASE=/
ARG VITE_API_BASE=/api
ARG VITE_PLATFORM=0
ENV VITE_BASE=$VITE_BASE VITE_API_BASE=$VITE_API_BASE VITE_PLATFORM=$VITE_PLATFORM
RUN npm run build

FROM nginxinc/nginx-unprivileged:1.27-alpine
COPY nginx.conf /etc/nginx/conf.d/default.conf
COPY --from=build /src/dist /usr/share/nginx/html
EXPOSE 8080
