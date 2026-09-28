FROM python:3.13-alpine@sha256:79e7a9b9ff1cbceff819f856fb374477792a5967759d94df266de7b7b4120e6f

WORKDIR /app
COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir --requirement /app/requirements.txt
COPY deny_ip_toolkit.py output_formats.py /app/

RUN addgroup -S app && adduser -S -G app app \
    && mkdir -p /app/output \
    && chown -R app:app /app

USER app
ENTRYPOINT ["python3", "/app/deny_ip_toolkit.py"]
