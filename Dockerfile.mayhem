FROM --platform=linux/amd64 ubuntu:20.04 as builder

RUN apt-get update
RUN DEBIAN_FRONTEND=noninteractive apt-get install -y build-essential

ADD . /MazuCC
WORKDIR /MazuCC
RUN make -j8

RUN mkdir -p /deps
RUN ldd /MazuCC/mzcc | tr -s '[:blank:]' '\n' | grep '^/' | xargs -I % sh -c 'cp % /deps;'

FROM ubuntu:20.04 as package

COPY --from=builder /deps /deps
COPY --from=builder /MazuCC/mzcc /MazuCC/mzcc
ENV LD_LIBRARY_PATH=/deps
