FROM nginx:1.27-alpine

COPY frontend/nginx.conf /etc/nginx/conf.d/default.conf
COPY frontend/index.html /usr/share/nginx/html/index.html
COPY frontend/js /usr/share/nginx/html/js
COPY frontend/styles /usr/share/nginx/html/styles

EXPOSE 80
