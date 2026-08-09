FROM python:3.13-slim

WORKDIR /app
COPY pyproject.toml README.md ./
COPY findai ./findai
RUN pip install --no-cache-dir .

ENV FINDAI_HOST=0.0.0.0
ENV FINDAI_DB_PATH=/data/findai.db
VOLUME ["/data"]
EXPOSE 7070

CMD ["findai"]

