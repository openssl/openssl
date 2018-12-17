SUBDIRS = bio cms evp pkcs12 smime

all: subdirs

subdirs:
	for dir in $(SUBDIRS); do \
		( cd $$dir; $(MAKE) OPENSSL_INCS_LOCATION=-I../../include OPENSSL_LIBS_LOCATION=-L../.. ); \
	done

clean:
	for dir in $(SUBDIRS); do \
		( cd $$dir; $(MAKE) clean ); \
	done
