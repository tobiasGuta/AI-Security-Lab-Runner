FROM alpine:3.20
RUN apk add --no-cache netcat-openbsd
USER nobody
EXPOSE 5432
CMD ["sh", "-c", "while true; do echo 'DB ready' | nc -l -p 5432; done"]
