FROM python:3.11-slim
RUN pip install --no-cache-dir "presidio-analyzer==2.2.355" "spacy==3.7.5" "typer==0.12.5" "click==8.1.7" \
 && pip install --no-cache-dir \
    "https://github.com/explosion/spacy-models/releases/download/en_core_web_lg-3.7.1/en_core_web_lg-3.7.1-py3-none-any.whl"
ENV TLDEXTRACT_CACHE=/opt/tldcache
RUN python -c "import tldextract; tldextract.TLDExtract(cache_dir='/opt/tldcache').update(fetch_now=True)" && chmod -R a+rwX /opt/tldcache
RUN useradd -m scanner
USER scanner
COPY --chown=scanner:scanner scan.py /app/scan.py
WORKDIR /app
ENTRYPOINT ["python", "/app/scan.py"]
