FROM debian:testing

RUN apt update \
    && apt install -y curl wget xz-utils build-essential gnuplot autoconf libtool pkg-config libssl-dev libmbedtls-dev \
       libcurl4 zlib1g-dev git cmake \
    && rm -rf /var/lib/apt/lists/* /tmp/*

# LDC compiler
# https://github.com/ldc-developers/ldc/releases
WORKDIR /opt
ARG LDC=1.25.1
RUN wget --progress=dot:giga -O - \
    https://github.com/ldc-developers/ldc/releases/download/v$LDC/ldc2-$LDC-linux-x86_64.tar.xz \
    | tar -xJ
ENV PATH="/opt/ldc2-$LDC-linux-x86_64/bin:${PATH}"

# jansson
RUN git clone https://github.com/akheron/jansson.git \
    && cd jansson && autoreconf -i && ./configure \
    && sed -i '/CFLAGS = .*/c\CFLAGS = -O3' Makefile \
    && make && make install \
    && cd .. && rm -rf jansson

# libjwt
RUN git clone https://github.com/benmcollins/libjwt.git \
    && cd libjwt && autoreconf -i && ./configure \
    && sed -i '/CFLAGS = .*/c\CFLAGS = -O3' Makefile \
    && sed -i '/SUBDIRS = .*/c\SUBDIRS = include libjwt' Makefile \
    && make && make install \
    && cd .. && rm -rf libjwt

ENV LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/usr/local/lib
WORKDIR /src/benchmarks
ENTRYPOINT [ "bash" ]

RUN cat /etc/os-release
