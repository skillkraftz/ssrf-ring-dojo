FROM python:3.11-slim

WORKDIR /app
COPY internal-admin/requirements.txt ./requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

COPY shared ./shared
COPY internal-admin/app.py .
COPY keys/token-service-public.pem /keys/token-service-public.pem
COPY keys/admin-exporter-public.pem /keys/admin-exporter-public.pem
COPY keys/admin-observer-public.pem /keys/admin-observer-public.pem
COPY tls/ca-cert.pem /tls/ca-cert.pem
COPY tls/internal-admin-server-cert.pem /tls/internal-admin-server-cert.pem
COPY tls/internal-admin-server-key.pem /tls/internal-admin-server-key.pem

EXPOSE 5001
CMD ["python", "app.py"]
