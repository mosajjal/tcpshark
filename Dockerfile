FROM alpine:edge
LABEL maintainer "Ali Mosajjal <hi@n0p.me>"

SHELL ["/bin/ash", "-c"]

RUN apk add --no-cache libcap-static libpcap-dev linux-headers git go file rpm --repository http://dl-cdn.alpinelinux.org/alpine/edge/testing/

ENV DST="/tmp/tcpshark/"
ENV REPO="github.com/mosajjal/tcpshark"
RUN git clone https://${REPO}.git ${DST} --depth 1 \
    && cd ${DST} \
    && go build --ldflags "-L /usr/lib/libcap.a -linkmode external -extldflags \"-static\"" -o ${DST}/tcpshark


FROM scratch
COPY --from=0 /tmp/tcpshark/tcpshark /tcpshark
ENTRYPOINT ["/tcpshark"]
