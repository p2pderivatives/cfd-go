FROM alpine:3.12

WORKDIR /workspace

ARG CFDGO_VER=v0.3.2

RUN apk add --update --no-cache musl gcc g++ make git cmake

RUN git clone https://github.com/p2pderivatives/cfd-go.git \
  && cd cfd-go \
  && git checkout refs/tags/$CFDGO_VER \
  && mkdir build \
  && cd build \
  && cmake .. -DENABLE_SHARED=on -DCMAKE_BUILD_TYPE=Release -DENABLE_TESTS=off -DENABLE_JS_WRAPPER=off -DENABLE_CAPI=on -DTARGET_RPATH=/usr/local/lib:/usr/local/lib64 \
  && make

RUN mkdir /workspace/dist \
  && cd /workspace/cfd-go/build \
  && make install DESTDIR=/workspace/dist \
  && rm -rf /workspace/cfd-go