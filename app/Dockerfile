FROM python:3.9-slim
WORKDIR /app
COPY app.py .
# Pin index + explicit timeout/retries: Docker Desktop buildkit DNS is flaky on WSL.
# If this still fails, build with `--network=host` (see Makefile rebuild-image).
RUN pip install --no-cache-dir --retries 5 --timeout 30 \
    -i https://pypi.org/simple \
    flask requests
CMD ["python", "app.py"]