FROM golang:1.16-alpine3.14

WORKDIR /workspace

RUN apk add --update --no-cache musl gcc g++ make swig git cmake

RUN go get github.com/golang/mock/gomock@v1.6.0 \
	&& go get github.com/golang/mock/mockgen@v1.6.0 \
	&& go get golang.org/x/tools/cmd/goimports@v0.1.5
