FROM nginx:alpine
COPY nginx.conf /etc/nginx/conf.d/default.conf
COPY index.html report.html style.css app.js /usr/share/nginx/html/
COPY .well-known/security.txt /usr/share/nginx/html/.well-known/security.txt
EXPOSE 80
