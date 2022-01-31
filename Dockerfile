FROM debian:stable-slim

ADD "https://github.com/percibe/redns/releases/download/linux-x64-latest/redns" "/redns"

RUN chmod +x /redns \
	&& apt-get update \
	&& apt-get install -y ca-certificates libicu-dev

WORKDIR /conf
VOLUME  /conf

ENTRYPOINT ["/redns"]
