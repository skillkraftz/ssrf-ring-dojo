FROM python:3.11-slim

WORKDIR /app
COPY internal-admin/requirements.txt ./requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

COPY shared ./shared
COPY internal-admin/app.py .

EXPOSE 5001
CMD ["python", "app.py"]
