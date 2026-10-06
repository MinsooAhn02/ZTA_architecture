FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir --retries 5 --timeout 30 -i https://pypi.org/simple -r requirements.txt
COPY app.py .
ENV PYTHONDONTWRITEBYTECODE=1
CMD ["python", "-B", "app.py"]
