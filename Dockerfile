FROM python:3.13-alpine

WORKDIR /app
COPY deny_ip_toolkit.py /app/deny_ip_toolkit.py

RUN addgroup -S app && adduser -S -G app app \
    && mkdir -p /app/output \
    && chown -R app:app /app

USER app
ENTRYPOINT ["python3", "/app/deny_ip_toolkit.py"]

