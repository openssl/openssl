
Must do a 
SSL_init_eay_ciphers();
before calls to SSL_CTX_new()

SSL_CTX *SSL_CTX_new(void ) -> SSL_CTX *SSL_CTX_new(SSL_METHOD *meth);

SSL_CTX_set_cert_verify_cb -> the callback is now
int callback(char *arg,SSL *s,X509 *xs,STACK *cert_chain);
where the 'cert_chain' has been added.
