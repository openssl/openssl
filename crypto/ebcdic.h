#ifndef HEADER_EBCDIC_H
#define HEADER_EBCDIC_H

#include <sys/types.h>

/* Avoid name clashes with other applications */
#define os_toascii   _eay2000_os_toascii
#define os_toebcdic  _eay2000_os_toebcdic
#define ebcdic2ascii _eay2000_ebcdic2ascii
#define ascii2ebcdic _eay2000_ascii2ebcdic

extern const unsigned char os_toascii[256];
extern const unsigned char os_toebcdic[256];
void ebcdic2ascii(unsigned char *dest, const unsigned char *srce, size_t count);
void ascii2ebcdic(unsigned char *dest, const unsigned char *srce, size_t count);

#endif
