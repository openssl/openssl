
#include "openssl.h"

static int p5_bio_ex_bio_ptr = 0;
static int p5_bio_ex_bio_callback = 0;
static int p5_bio_ex_bio_callback_data = 0;

static long 
p5_bio_callback(bio,state,parg,cmd,larg,ret)
  BIO  *bio;
  int   state;
  char *parg;
  int   cmd;
  long  larg;
  int   ret;
{
    int i;
    SV *me,*cb;

    me = (SV *)BIO_get_ex_data(bio, p5_bio_ex_bio_ptr);
    cb = (SV *)BIO_get_ex_data(bio, p5_bio_ex_bio_callback);
    if (cb != NULL) {
        dSP;

        ENTER;
        SAVETMPS;

        PUSHMARK(sp);
        XPUSHs(sv_2mortal(newSVsv(me)));
        XPUSHs(sv_2mortal(newSViv(state)));
        XPUSHs(sv_2mortal(newSViv(cmd)));
        if ((state == BIO_CB_READ) || (state == BIO_CB_WRITE))
            XPUSHs(sv_2mortal(newSVpv(parg,larg)));
        else
            XPUSHs(&sv_undef);
        /* ptr one */
        XPUSHs(sv_2mortal(newSViv(larg)));
        XPUSHs(sv_2mortal(newSViv(ret)));
        PUTBACK;

        i = perl_call_sv(cb,G_SCALAR);

        SPAGAIN;
        if (i == 1)
            ret = POPi;
        else
            ret = 1;
        PUTBACK;
        FREETMPS;
        LEAVE;
    }
    else {
        croak("Internal error in p5_bio_callback");
    }
    return(ret);
}

int 
boot_bio(void)
{
    p5_bio_ex_bio_ptr = BIO_get_ex_new_index(0, "OpenSSL::BIO", ex_new, NULL, ex_cleanup);
    p5_bio_ex_bio_callback = BIO_get_ex_new_index(0, "bio_callback", NULL, NULL, ex_cleanup);
    p5_bio_ex_bio_callback_data = BIO_get_ex_new_index(0, "bio_callback_data", NULL, NULL, ex_cleanup);
    return(1);
}

MODULE = OpenSSL::BIO  PACKAGE = OpenSSL::BIO  PREFIX = p5_BIO_

PROTOTYPES: ENABLE
VERSIONCHECK: DISABLE

void
p5_BIO_new_buffer_ssl_connect(...)
    PROTOTYPE: ;$
    PREINIT:
        SSL_CTX *ctx;
        BIO *bio;
        SV *arg;
    PPCODE:
        if (items == 1)
            arg = ST(0);
        else if (items == 2)
            arg = ST(1);
        else
            arg = NULL;
        if ((arg == NULL) || !(sv_derived_from(arg,"OpenSSL::SSL::CTX")))
            croak("Usage: OpenSSL::BIO::new_buffer_ssl_connect(SSL_CTX)");
        else {
            IV tmp = SvIV((SV *)SvRV(arg));
            ctx = (SSL_CTX *)tmp;
        }
        EXTEND(sp, 1);
        bio = BIO_new_buffer_ssl_connect(ctx);
        arg = (SV *)BIO_get_ex_data(bio, p5_bio_ex_bio_ptr);
        PUSHs(arg);
    
void
p5_BIO_new_ssl_connect(...)
    PROTOTYPE: ;$
    PREINIT:
        SSL_CTX *ctx;
        BIO *bio;
        SV *arg;
    PPCODE:
        if (items == 1)
            arg = ST(0);
        else if (items == 2)
            arg = ST(1);
        else
            arg = NULL;
        if ((arg == NULL) || !(sv_derived_from(arg,"OpenSSL::SSL::CTX")))
            croak("Usage: OpenSSL::BIO::new_ssl_connect(SSL_CTX)");
        else {
            IV tmp = SvIV((SV *)SvRV(arg));
            ctx = (SSL_CTX *)tmp;
        }
        EXTEND(sp,1);
        bio = BIO_new_ssl_connect(ctx);
        arg = (SV *)BIO_get_ex_data(bio,p5_bio_ex_bio_ptr);
        PUSHs(arg);
    
void
p5_BIO_new(...)
    PROTOTYPE: ;$
    PREINIT:
        BIO *bio;
        char *type;
        SV *arg;
    PPCODE:
        pr_name("p5_BIO_new");
        if ((items == 1) && SvPOK(ST(0)))
            type = SvPV(ST(0),na);
        else if ((items == 2) && SvPOK(ST(1)))
            type = SvPV(ST(1),na);
        else
            croak("Usage: OpenSSL::BIO::new(type)");
        EXTEND(sp,1);
        if (strcmp(type, "mem") == 0)
            bio=BIO_new(BIO_s_mem());
        else if (strcmp(type, "socket") == 0)
            bio=BIO_new(BIO_s_socket());
        else if (strcmp(type, "connect") == 0)
            bio=BIO_new(BIO_s_connect());
        else if (strcmp(type, "accept") == 0)
            bio=BIO_new(BIO_s_accept());
        else if (strcmp(type, "fd") == 0)
            bio=BIO_new(BIO_s_fd());
        else if (strcmp(type, "file") == 0)
            bio=BIO_new(BIO_s_file());
        else if (strcmp(type, "null") == 0)
            bio=BIO_new(BIO_s_null());
        else if (strcmp(type, "ssl") == 0)
            bio=BIO_new(BIO_f_ssl());
        else if (strcmp(type, "buffer") == 0)
            bio=BIO_new(BIO_f_buffer());
        else
            croak("unknown BIO type");
        arg = (SV *)BIO_get_ex_data(bio,p5_bio_ex_bio_ptr);
        PUSHs(arg);

int
p5_BIO_hostname(bio, name)
    BIO *bio;
    char *name;
    PROTOTYPE: $$
    CODE:
        RETVAL = BIO_set_conn_hostname(bio, name);
    OUTPUT:
        RETVAL

int
p5_BIO_set_accept_port(bio, str)
    BIO *bio;
    char *str;
    PROTOTYPE: $$
    CODE:
        RETVAL = BIO_set_accept_port(bio, str);
    OUTPUT:
        RETVAL

int
p5_BIO_do_handshake(bio)
    BIO *bio;
    PROTOTYPE: $
    CODE:
        RETVAL = BIO_do_handshake(bio);
    OUTPUT:
        RETVAL

BIO *
p5_BIO_push(b, bio)
    BIO *b;
    BIO *bio;
    PROTOTYPE: $$
    CODE:
        /* This reference will be reduced when the reference is
         * let go, and then when the BIO_free_all() is called
         * inside the OpenSSL library by the BIO with this
         * pushed into */
        bio->references++;
        RETVAL = BIO_push(b, bio);
    OUTPUT:
        RETVAL

void
p5_BIO_pop(b)
    BIO *b
    PROTOTYPE: $
    PREINIT:
        BIO *bio;
        char *type;
        SV *arg;
    PPCODE:
        bio = BIO_pop(b);
        if (bio != NULL) {
            /* This BIO will either be one created in the
             * perl library, in which case it will have a perl
             * SV, otherwise it will have been created internally,
             * inside OpenSSL.  For the 'pushed in', it needs
             * the reference count decremented. */
            arg = (SV *)BIO_get_ex_data(bio, p5_bio_ex_bio_ptr);
            if (arg == NULL) {
                arg = new_ref("OpenSSL::BIO",(char *)bio,0);
                BIO_set_ex_data(bio, p5_bio_ex_bio_ptr, (char *)arg);
                PUSHs(arg);
            }
            else {
                /* it was pushed in */
                SvREFCNT_inc(arg);
                PUSHs(arg);
            }
        }

int
p5_BIO_sysread(bio, in, num, ...)
    BIO *bio;
    SV *in;
    int num;
    PROTOTYPE: $$$;
    PREINIT:
        int i,n,olen;
        int offset;
        char *p;
    CODE:
        offset = 0;
        if (!SvPOK(in))
            sv_setpvn(in, "", 0);
        SvPV(in, olen);
        if (items > 3) {
            offset = SvIV(ST(3));
            if (offset < 0) {
                if (-offset > olen)
                    croak("Offset outside string");
                offset+=olen;
            }
        }
        if ((num+offset) > olen) {
            SvGROW(in, num+offset+1);
            p=SvPV(in, i);
            memset(&(p[olen]), 0, (num+offset)-olen+1);
        }
        p = SvPV(in,n);
        i = BIO_read(bio, p+offset, num);
        RETVAL = i;
        if (i <= 0) 
            i = 0;
        SvCUR_set(in, offset+i);
    OUTPUT:
        RETVAL

int
p5_BIO_syswrite(bio, in, ...)
    BIO *bio;
    SV *in;
    PROTOTYPE: $$;
    PREINIT:
        char *ptr;
        int len,in_len;
        int offset=0;
        int n;
    CODE:
        ptr = SvPV(in, in_len);
        if (items > 2) {
            len = SvOK(ST(2)) ? SvIV(ST(2)) : in_len;
            if (items > 3) {
                offset = SvIV(ST(3));
                if (offset < 0) {
                    if (-offset > in_len)
                        croak("Offset outside string");
                    offset+=in_len;
                }
                else if ((offset >= in_len) && (in_len > 0))
                    croak("Offset outside string");
            }
            if (len >= (in_len-offset))
                len = in_len-offset;
        }
        else
            len = in_len;
        RETVAL = BIO_write(bio, ptr+offset, len);
    OUTPUT:
        RETVAL

void
p5_BIO_getline(bio)
    BIO *bio;
    PROTOTYPE: $
    PREINIT:
        int i;
        char *p;
    PPCODE:
        pr_name("p5_BIO_gets");
        EXTEND(sp, 1);
        PUSHs(sv_newmortal());
        sv_setpvn(ST(0), "", 0);
        SvGROW(ST(0), 1024);
        p=SvPV(ST(0), na);
        i = BIO_gets(bio, p, 1024);
        if (i < 0) 
            i = 0;
        SvCUR_set(ST(0), i);

int
p5_BIO_flush(bio)
    BIO *bio;
    PROTOTYPE: $
    CODE:
        RETVAL = BIO_flush(bio);
    OUTPUT:
        RETVAL

char *
p5_BIO_type(bio)
    BIO *bio;
    PROTOTYPE: $
    CODE:
        RETVAL = bio->method->name;
    OUTPUT:
        RETVAL

void
p5_BIO_next_bio(b)
    BIO *b
    PROTOTYPE: $
    PREINIT:
        BIO *bio;
        char *type;
        SV *arg;
    PPCODE:
        bio = b->next_bio;
        if (bio != NULL) {
            arg = (SV *)BIO_get_ex_data(bio, p5_bio_ex_bio_ptr);
            if (arg == NULL) {
                arg = new_ref("OpenSSL::BIO", (char *)bio, 0);
                BIO_set_ex_data(bio, p5_bio_ex_bio_ptr, (char *)arg);
                bio->references++;
                PUSHs(arg);
            }
            else {
                SvREFCNT_inc(arg);
                PUSHs(arg);
            }
        }

int
p5_BIO_puts(bio, in)
    BIO *bio;
    SV *in;
    PROTOTYPE: $$
    PREINIT:
        char *ptr;
    CODE:
        ptr = SvPV(in,na);
        RETVAL = BIO_puts(bio, ptr);
    OUTPUT:
        RETVAL

void
p5_BIO_set_callback(bio, cb,...)
    BIO *bio;
    SV *cb;
    PROTOTYPE: $$;
    PREINIT:
        SV *arg  = NULL;
        SV *arg2 = NULL;
    CODE:
        if (items > 3)
            croak("Usage: OpenSSL::BIO::set_callback(bio,callback[,arg]");
        if (items == 3) {
            arg2 = sv_mortalcopy(ST(2));
            SvREFCNT_inc(arg2);
            BIO_set_ex_data(bio, p5_bio_ex_bio_callback_data, (char *)arg2);
        }
        arg = sv_mortalcopy(ST(1));
        SvREFCNT_inc(arg);
        BIO_set_ex_data(bio, p5_bio_ex_bio_callback, (char *)arg);
        /* printf("%08lx < bio_ptr\n",BIO_get_ex_data(bio,p5_bio_ex_bio_ptr)); */
        BIO_set_callback(bio, p5_bio_callback);

void
p5_BIO_DESTROY(bio)
    BIO *bio
    PROTOTYPE: $
    PREINIT:
        SV *sv;
    PPCODE:
        pr_name_d("p5_BIO_DESTROY",bio->references);
        /* printf("p5_BIO_DESTROY <%s> %d\n",bio->method->name,bio->references); */
        BIO_set_ex_data(bio,p5_bio_ex_bio_ptr,NULL);
        BIO_free_all(bio);

int
p5_BIO_set_ssl(bio, ssl)
    BIO *bio;
    SSL *ssl;
    PROTOTYPE: $$
    CODE:
        pr_name("p5_BIO_set_ssl");
        ssl->references++;
        RETVAL = BIO_set_ssl(bio, ssl, BIO_CLOSE);
    OUTPUT:
        RETVAL

int
p5_BIO_number_read(bio)
    BIO *bio;
    PROTOTYPE: $
    CODE:
        RETVAL = BIO_number_read(bio);
    OUTPUT:
        RETVAL

int
p5_BIO_number_written(bio)
    BIO *bio;
    PROTOTYPE: $
    CODE:
        RETVAL = BIO_number_written(bio);
    OUTPUT:
        RETVAL

int
p5_BIO_references(bio)
    BIO *bio;
    PROTOTYPE: $
    CODE:
        RETVAL = bio->references; 
    OUTPUT:
        RETVAL

