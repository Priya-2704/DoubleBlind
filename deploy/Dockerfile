# One image for every role; the command decides which component runs.
# No wheels are installed because the project is standard library only, which
# also means there is no dependency surface to audit in this image.
FROM python:3.12-slim

# Run as a non-root user with no login shell and no home to write into.
RUN useradd --system --no-create-home --shell /usr/sbin/nologin doubleblind

WORKDIR /app
COPY doubleblind/ /app/doubleblind/
COPY scripts/ /app/scripts/

# The audit log is the only path the gateway writes, and it is mounted in.
RUN mkdir -p /artifacts && chown doubleblind:doubleblind /artifacts

USER doubleblind
ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1

# Overridden per service in docker-compose.yml.
CMD ["python", "-m", "doubleblind.gateway", "--help"]
