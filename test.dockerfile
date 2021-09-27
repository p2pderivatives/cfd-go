FROM golang:1.15-alpine3.12

WORKDIR /workspace

ARG CFDGO_DOMAIN=cryptogarageinc
ARG CFDGO_VER=v0.3.2

RUN apk add --update --no-cache musl gcc g++ make unzip wget \
  && echo "---- download cfd binary ----" \
  && wget https://github.com/$CFDGO_DOMAIN/cfd-go/releases/download/$CFDGO_VER/cfdgo-$CFDGO_VER-alpine_x86_64.zip \
  && unzip -d / cfdgo-$CFDGO_VER-alpine-3.12-x86_64.zip

RUN echo "---- test cfd-go ----" \
  && apk add --update --no-cache git \
  && git clone https://github.com/$CFDGO_DOMAIN/cfd-go.git \
  && cd cfd-go \
  && git checkout refs/tags/$CFDGO_VER \
  && echo "---- go test start ----" \
  && LD_LIBRARY_PATH="$LD_LIBRARY_PATH:/usr/local/lib64:/usr/local/lib" /usr/local/go/bin/go mod download \
  && LD_LIBRARY_PATH="$LD_LIBRARY_PATH:/usr/local/lib64:/usr/local/lib" /usr/local/go/bin/go build \
  && LD_LIBRARY_PATH="$LD_LIBRARY_PATH:/usr/local/lib64:/usr/local/lib" /usr/local/go/bin/go test \
  && echo "---- go test end ----"