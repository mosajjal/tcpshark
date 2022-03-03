FROM alpine:edge
LABEL maintainer "Ali Mosajjal <hi@n0p.me>"

SHELL ["/bin/ash", "-c"]

RUN apk add --no-cache libcap-static libpcap-dev linux-headers git go file rpm --repository http://dl-cdn.alpinelinux.org/alpine/edge/testing/

ENV DST="/tmp/tcpshark/"
ENV REPO="github.com/mosajjal/tcpshark"
RUN git clone https://${REPO}.git ${DST} --depth 1 \
    && cd ${DST} \
    && go build --ldflags "-L /usr/lib/libcap.a -linkmode external -extldflags \"-static\"" -o ${DST}/tcpshark-linux-amd64.bin


ENV CGO_ENABLED=1
ENV GOOS=windows
ENV GOARCH=amd64
RUN sh -c 'cd ${DST} && go build -o ${DST}/dnsmonster-windows-amd64.exe'

