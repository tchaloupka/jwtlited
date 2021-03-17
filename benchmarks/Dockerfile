FROM debian:testing

RUN apt update \
    && apt install -y --no-install-recommends \
       curl wget xz-utils build-essential gnuplot-nox autoconf automake libtool pkg-config libssl-dev \
       libcurl4 zlib1g-dev git ca-certificates cmake \
    && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

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

# l8w8jwt
RUN git clone --recursive https://github.com/GlitchedPolygons/l8w8jwt.git \
    && cd l8w8jwt  \
    && mkdir -p build && cd build \
    && cmake -DBUILD_SHARED_LIBS=Off -DL8W8JWT_PACKAGE=On -DCMAKE_BUILD_TYPE=Release .. \
    && cmake --build . --config Release \
    && cp l8w8jwt/bin/release/libl8w8jwt.a /usr/local/lib/ \
    && cp mbedtls/library/*.a /usr/local/lib/ \
    && cd ../.. && rm -rf l8w8jwt

ENV LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/usr/local/lib
WORKDIR /src/benchmarks
ENTRYPOINT [ "bash" ]

RUN cat /etc/os-release
