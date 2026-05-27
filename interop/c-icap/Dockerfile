FROM debian:bookworm-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends c-icap \
    && rm -rf /var/lib/apt/lists/*

COPY c-icap.conf /etc/c-icap/c-icap.conf

EXPOSE 1344

CMD ["c-icap", "-N", "-D", "-d", "3", "-f", "/etc/c-icap/c-icap.conf"]
