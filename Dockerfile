FROM python:3.12-slim-bookworm

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    HOME=/home/runner

WORKDIR /opt/runner
COPY pyproject.toml README.md LICENSE ./
COPY vardrrunner ./vardrrunner
RUN pip install --no-cache-dir . \
    && useradd --uid 10001 --create-home runner \
    && mkdir -p /home/runner/.vardrmap \
    && chown runner:runner /home/runner/.vardrmap \
    && chmod 700 /home/runner/.vardrmap

USER 10001:10001
WORKDIR /home/runner
ENTRYPOINT ["vardrrunner"]
CMD ["--help"]
