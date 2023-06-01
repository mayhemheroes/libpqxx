FROM --platform=linux/amd64 ubuntu:22.04 as builder

RUN apt-get update
RUN DEBIAN_FRONTEND=noninteractive apt-get install -y build-essential clang cmake pkg-config libpq-dev

COPY . /repo
WORKDIR /repo/build
RUN cmake .. -DSKIP_BUILD_TEST=on -DBUILD_SHARED_LIBS=off
RUN make -j8
RUN make install

RUN clang++ /repo/mayhem/fuzz_append.cpp -fsanitize=fuzzer,address  -std=c++17 /repo/build/src/libpqxx.a -o /fuzz

FROM ubuntu:22.04 as package

COPY --from=builder /fuzz /fuzz_append
