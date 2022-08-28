FROM gcc:9.5.0-buster
RUN apt update && apt install -y build-essential perl libtext-template-perl
COPY . /opt/src/openssl
WORKDIR /opt/src/openssl
RUN ["./Configure", "--prefix=/opt/openssl-static/openssl", "--openssldir=/opt/openssl-static/ssl", "--static", "-static"]
RUN ["make"]
RUN ["make", "install"]
