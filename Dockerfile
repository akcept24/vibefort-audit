FROM python:3.12-alpine
RUN apk add --no-cache curl
WORKDIR /app
COPY server.py email_template.py index.html report.html terms.html privacy.html style.css app.js favicon.svg robots.txt sitemap.xml /app/
COPY .well-known/security.txt /app/.well-known/security.txt
ENV PORT=80 VF_DB_PATH=/data/vibefort.db
EXPOSE 80
CMD ["python3", "server.py"]
