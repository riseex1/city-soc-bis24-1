# Район «Городской SOC». Образ собирается командой: docker compose up --build -d
FROM python:3.12-slim

# Непривилегированный пользователь (урок ЛР0): процесс в контейнере — не root
RUN useradd --uid 10001 --create-home --shell /usr/sbin/nologin appuser

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY citykit ./citykit
COPY app ./app
RUN mkdir -p /data && chown appuser /data

USER appuser
ENV DATA_DIR=/data PYTHONUNBUFFERED=1
EXPOSE 8000
HEALTHCHECK --interval=15s --timeout=3s \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/health', timeout=2)"
# Один процесс и 4 потока: подключение к Транспорту одно на район.
CMD ["gunicorn", "--workers", "1", "--threads", "4", "--bind", "0.0.0.0:8000", "app:create_app()"]
