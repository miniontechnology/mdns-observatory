FROM python:3.12-slim

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt \
 && useradd -r -u 1000 app && mkdir -p /data && chown app:app /data
COPY app.py .
COPY static/ static/

USER app
EXPOSE 8053
CMD ["python3", "-u", "app.py"]
