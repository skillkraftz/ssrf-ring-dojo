FROM python:3.11-slim

WORKDIR /app
COPY token-service/requirements.txt ./requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

COPY shared ./shared
COPY token-service/app.py .
COPY keys/token-service-private.pem /keys/token-service-private.pem
COPY keys/admin-exporter-public.pem /keys/admin-exporter-public.pem
COPY keys/admin-observer-public.pem /keys/admin-observer-public.pem

EXPOSE 5003
CMD ["python", "app.py"]
