FROM martenseemann/quic-network-simulator-endpoint:latest

# Make sure curl picks up the new openssl
ENV PKG_CONFIG_LIBDIR=/usr/lib64/pkgconfig:/usr/lib/pkgconfig:/usr/lib/x86_64-linux-gnu/pkgconfig/:$PKG_CONFIG_LIBDIR
# Set the environment variable LD_LIBRARY_PATH to ensure we get the right libraries
ENV LD_LIBRARY_PATH=/usr/lib64:/usr/lib:/usr/lib/x86_64-linux-gnu:$LD_LIBRARY_PATH

# Install needed tools
RUN apt-get update && apt-get install -y \
    git make gcc perl cmake build-essential \
    autoconf libtool pkg-config libpsl-dev

WORKDIR /

# build nghttp3
RUN git clone https://github.com/ngtcp2/nghttp3.git && \
    cd nghttp3 && \
    git submodule update --init && \
    autoreconf -i && \
    ./configure --prefix=/usr && \
    make -j 4 check && \
    make install && \
    rm -rf /nghttp3

# download and build openssl 
RUN git clone https://github.com/openssl/openssl.git && \
    cd openssl && \
    ./Configure enable-fips no-docs --prefix=/usr --openssldir=/etc/pki/tls && \
    make -j 4 && make install && \
    rm -rf /openssl

# Build curl
RUN git clone https://github.com/curl/curl.git && \
    cd curl && \
    autoreconf -fi && ./configure --with-openssl-quic --with-openssl --with-nghttp3 --prefix=/usr && \
    make -j 4 && \
    make install && \
    rm -rf /curl

# copy run script and run it
COPY run_endpoint.sh .
RUN chmod +x run_endpoint.sh
RUN apt-get clean
ENTRYPOINT [ "./run_endpoint.sh" ]

