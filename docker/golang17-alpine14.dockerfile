FROM golang:1.17-alpine3.14

WORKDIR /workspace

RUN apk add --update --no-cache musl gcc g++ make git cmake
