FROM python:3.11-slim

WORKDIR /app
COPY ops-client/requirements.txt ./requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

COPY shared ./shared
COPY ops-client/tests ./tests
COPY keys/admin-exporter-private.pem /keys/admin-exporter-private.pem
COPY keys/admin-observer-private.pem /keys/admin-observer-private.pem

CMD ["python", "-c", "import time; time.sleep(10**9)"]
