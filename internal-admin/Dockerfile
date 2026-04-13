FROM python:3.11-slim

WORKDIR /app
COPY internal-admin/requirements.txt ./requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

COPY shared ./shared
COPY internal-admin/app.py .
COPY keys/token-service-public.pem /keys/token-service-public.pem
COPY keys/admin-exporter-public.pem /keys/admin-exporter-public.pem
COPY keys/admin-observer-public.pem /keys/admin-observer-public.pem

EXPOSE 5001
CMD ["python", "app.py"]
