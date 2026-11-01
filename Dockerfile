FROM python:3.12-alpine
RUN apk add --no-cache curl
WORKDIR /app
COPY server.py index.html report.html style.css app.js /app/
COPY .well-known/security.txt /app/.well-known/security.txt
ENV PORT=80 VF_DB_PATH=/data/vibefort.db
EXPOSE 80
CMD ["python3", "server.py"]
