FROM alpine:edge

RUN mkdir -p /app
COPY proxy /app


RUN apk add 'tor' --no-cache \
  --repository http://dl-cdn.alpinelinux.org/alpine/edge/community \
  --repository http://dl-cdn.alpinelinux.org/alpine/edge/main \
  --allow-untrusted haproxy privoxy python3 python3-dev py3-pip alpine-sdk libffi-dev openssl-dev \
                                            && rm -rf /var/cache/apk/* \
                                            && pip3 install -r /app/requirements.txt \
                                            && chmod +x /app/tor.py \
                                            && apk del alpine-sdk libffi-dev openssl-dev
WORKDIR /app

CMD python3 tor.py