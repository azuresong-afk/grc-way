FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1 \
    GRC_REFERENCE_DIR=/srv/reference GRC_EVIDENCE_DIR=/data/evidence GRC_BDU_DIR=/data/bdu GRC_SZI_DIR=/data/szi \
    GRC_DOCUMENTS_DIR=/data/documents GRC_TEMPLATES_DIR=/srv/templates/docx
WORKDIR /srv

# LibreOffice (без графики) — DOCX → PDF для документов комплекта; шрифты с кириллицей.
# Liberation метрически совместимы с Times New Roman и Arial из шаблонов.
RUN apt-get update \
 && apt-get install -y --no-install-recommends libreoffice-writer-nogui fonts-liberation fonts-dejavu-core \
 && rm -rf /var/lib/apt/lists/*

RUN groupadd --system grc && useradd --system --gid grc --home /srv grc

# Контекст сборки — корень репозитория (нужен каталог reference/).
COPY backend/pyproject.toml ./
COPY backend/app ./app
RUN pip install .

COPY backend/alembic.ini ./
COPY backend/alembic ./alembic
COPY reference ./reference
COPY templates ./templates
COPY backend/docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
RUN chmod 0755 /usr/local/bin/docker-entrypoint.sh && mkdir -p /data/evidence /data/bdu /data/szi /data/documents && chown -R grc:grc /data

USER grc
EXPOSE 8000
HEALTHCHECK --interval=15s --timeout=5s --start-period=20s --retries=5 \
  CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/health/ready').status==200 else 1)"
ENTRYPOINT ["docker-entrypoint.sh"]
CMD ["uvicorn", "app.main:create_app", "--factory", "--host", "0.0.0.0", "--port", "8000", "--proxy-headers"]
