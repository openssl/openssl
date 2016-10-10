all: ossl_shim

ossl_shim: ../../libssl.a ../../libcrypto.a *.cc
	g++ -g -std=c++11 -I. -I../../include *.cc \
	../../libssl.a ../../libcrypto.a -ldl -lpthread \
	-o ossl_shim

clean:
	rm ossl_shim
