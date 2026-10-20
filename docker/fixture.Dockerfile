FROM python:3.12-slim@sha256:f77ac9e44ae96ef2c90b8053ea08c31f8be030f824196b0ae4db6d462c84e51f

RUN python -m pip install --no-cache-dir \
    pytest==8.4.2 \
    iniconfig==2.3.0 \
    packaging==26.3 \
    pluggy==1.6.0 \
    pygments==2.21.0

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTEST_DISABLE_PLUGIN_AUTOLOAD=1
WORKDIR /workspace
USER 65534:65534

ENTRYPOINT ["python", "-m", "pytest", "-q", "-p", "no:cacheprovider"]
