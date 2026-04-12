FROM python:3.11-slim

WORKDIR /app
COPY token-service/requirements.txt ./requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

COPY shared ./shared
COPY token-service/app.py .
COPY token-service/tests ./tests

EXPOSE 5003
CMD ["python", "app.py"]
