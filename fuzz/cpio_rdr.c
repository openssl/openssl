/*
 * Copyright 2018 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL licenses, (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * https://www.openssl.org/source/license.html
 * or in the file LICENSE in the source distribution.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#include <limits.h>
#ifndef PATH_MAX
# define PATH_MAX 4096
#endif

#include <openssl/crypto.h>

#include "cpio_rdr.h"

/*
 * All data on the different CPIO formats came from cpio(5), commonly
 * distributed with libarchive.
 */
struct cpio_reader_st {
    /* Function that checks if it's a CPIO format this reader recognises */
    size_t (*headersize)(void *cpio_header);
    size_t (*filenamesize)(void *cpio_header);
    size_t (*datasize)(void *cpio_header);
    unsigned int align;
    size_t (*checksum_size)(void);
    void (*checksum_init)(void *cpio_header, void *expected, void *calculated);
    int (*checksum_update)(void *calculated, void *ptr, size_t size);
    int (*checksum_final)(void *expected, void *calculated);
};

/* Old binary */
struct header_old_cpio {
    uint16_t c_magic;
    uint16_t c_dev;
    uint16_t c_ino;
    uint16_t c_mode;
    uint16_t c_uid;
    uint16_t c_gid;
    uint16_t c_nlink;
    uint16_t c_rdev;
    uint16_t c_mtime[2];
    uint16_t c_namesize;
    uint16_t c_filesize[2];
};

static uint16_t old_swap(uint16_t v)
{
    return (v >> 8) | ((v & 0xff) << 8);
}
static size_t old_headersize(void *cpio_header) {
    struct header_old_cpio *h = (struct header_old_cpio *)cpio_header;

    if (h->c_magic == 070707     /* same endianness as host */
        || old_swap(h->c_magic) == 070707) /* opposite endianness */
        return sizeof(*h);
    return 0;
}

static size_t old_filenamesize(void *cpio_header) {
    struct header_old_cpio *h = (struct header_old_cpio *)cpio_header;

    if (h->c_magic == 070707)
        return h->c_namesize;
    return old_swap(h->c_namesize);
}

static size_t old_datasize(void *cpio_header) {
    struct header_old_cpio *h = (struct header_old_cpio *)cpio_header;

    if (h->c_magic == 070707)
        return h->c_filesize[0] << 16 | h->c_filesize[1];
    return old_swap(h->c_filesize[0]) << 16 | old_swap(h->c_filesize[1]);
}

static const struct cpio_reader_st cpio_old = {
    old_headersize, old_filenamesize, old_datasize, 2,
    NULL, NULL, NULL, NULL
};

/* Portable ASCII */
struct cpio_odc_header {
    char c_magic[6];
    char c_dev[6];
    char c_ino[6];
    char c_mode[6];
    char c_uid[6];
    char c_gid[6];
    char c_nlink[6];
    char c_rdev[6];
    char c_mtime[11];
    char c_namesize[6];
    char c_filesize[11];
};

static uint64_t octstr2uint64(const char *str, size_t len)
{
    uint64_t val = 0;

    OPENSSL_assert(len <= 11);
    while (len-- > 0) {
        unsigned char c = *str++;

#ifdef CHARSET_EBCDIC
        c = os_toebcdic[c];
#endif

        switch (c) {
        case '0':
            c = 0;
            break;
        case '1':
            c = 1;
            break;
        case '2':
            c = 2;
            break;
        case '3':
            c = 3;
            break;
        case '4':
            c = 4;
            break;
        case '5':
            c = 5;
            break;
        case '6':
            c = 6;
            break;
        case '7':
            c = 7;
            break;
        }
        val = (val << 3) | c;
    }

    return val;
}

static size_t odc_headersize(void *cpio_header) {
    struct cpio_odc_header *h = (struct cpio_odc_header *)cpio_header;

    return
        strncmp(h->c_magic, "070707", sizeof(h->c_magic)) == 0 ? sizeof(*h) : 0;
}

static size_t odc_filenamesize(void *cpio_header) {
    struct cpio_odc_header *h = (struct cpio_odc_header *)cpio_header;

    return octstr2uint64(h->c_namesize, sizeof(h->c_namesize));
}

static size_t odc_datasize(void *cpio_header) {
    struct cpio_odc_header *h = (struct cpio_odc_header *)cpio_header;


    return octstr2uint64(h->c_filesize, sizeof(h->c_filesize));
}

static const struct cpio_reader_st cpio_odc = {
    odc_headersize, odc_filenamesize, odc_datasize, 1,
    NULL, NULL, NULL, NULL
};

/* New ASCII format */
struct cpio_newc_header {
    char c_magic[6];
    char c_ino[8];
    char c_mode[8];
    char c_uid[8];
    char c_gid[8];
    char c_nlink[8];
    char c_mtime[8];
    char c_filesize[8];
    char c_devmajor[8];
    char c_devminor[8];
    char c_rdevmajor[8];
    char c_rdevminor[8];
    char c_namesize[8];
    char c_check[8];
};

static uint32_t hexstr2uint32(const char *str, size_t len)
{
    uint32_t val = 0;

    OPENSSL_assert(len <= 8);
    while (len-- > 0) {
        val = (val << 4) | OPENSSL_hexchar2int(*str++);
    }

    return val;
}

static size_t newc_headersize(void *cpio_header) {
    struct cpio_newc_header *h = (struct cpio_newc_header *)cpio_header;

    return
        strncmp(h->c_magic, "070701", sizeof(h->c_magic)) == 0 ? sizeof(*h) : 0;
}

static size_t newc_filenamesize(void *cpio_header) {
    struct cpio_newc_header *h = (struct cpio_newc_header *)cpio_header;

    return hexstr2uint32(h->c_namesize, sizeof(h->c_namesize));
}

static size_t newc_datasize(void *cpio_header) {
    struct cpio_newc_header *h = (struct cpio_newc_header *)cpio_header;

    return hexstr2uint32(h->c_filesize, sizeof(h->c_filesize));
}

static const struct cpio_reader_st cpio_newc = {
    newc_headersize, newc_filenamesize, newc_datasize, 4,
    NULL, NULL, NULL, NULL
};

static size_t newchksum_headersize(void *cpio_header)
{
    struct cpio_newc_header *h = (struct cpio_newc_header *)cpio_header;

    return
        strncmp(h->c_magic, "070702", sizeof(h->c_magic)) == 0 ? sizeof(*h) : 0;
}

static size_t newchksum_size(void)
{
    return sizeof(uint32_t);
}

static void newchksum_init(void *cpio_header, void *expected, void *calculated)
{
    struct cpio_newc_header *h = (struct cpio_newc_header *)cpio_header;

    *(uint32_t *)expected = hexstr2uint32(h->c_check, sizeof(h->c_check));
    *(uint32_t *)calculated = 0;
}

static int newchksum_update(void *calculated, void *ptr, size_t size)
{
    uint32_t calc = 0;
    unsigned char *p = ptr;

    for (; size > 0; p++, size--) {
        calc += p[0];
    }
    *(uint32_t *)calculated += calc;
    return 1;
}

static int newchksum_final(void *expected, void *calculated)
{
    return *(uint32_t *)calculated == *(uint32_t *)expected;
}

static const struct cpio_reader_st cpio_newchksum = {
    newchksum_headersize, newc_filenamesize, newc_datasize, 4,
    newchksum_size, newchksum_init, newchksum_update, newchksum_final
};

static const struct cpio_reader_st *cpio_reader_list[] = {
    &cpio_old,
    &cpio_odc,
    &cpio_newc,
    &cpio_newchksum,
    NULL
};

/**********************************************************************/

/* Main library */

struct cpio_st {
    FILE *file;
    enum {
        CPIO_AT_HEADER,
        CPIO_IN_FILE
    } state;
    size_t headeroffset;        /* Position of last header in cpio file */
    size_t rel_filenameoffset;  /* File name offset relative to header offset */
    size_t rel_dataoffset;      /* data offset relative to header offset */
    size_t datasize;            /* The data size given from header */
    size_t datasize_aligned;    /* data size including alignment bytes */
    size_t cur_readoffset;      /* read position relative to data offset */
    const struct cpio_reader_st *reader;
    int error;
    int eof;
    int archive_eof;
};

CPIO *cpio_open(const char *pathname)
{
    FILE *f = fopen(pathname, "rb");
    CPIO *cpio = NULL;

    if (f == NULL)
        return NULL;

    cpio = OPENSSL_zalloc(sizeof(*cpio));
    cpio->file = f;
    cpio->state = CPIO_AT_HEADER;
    return cpio;
}

const char *cpio_readentry(CPIO *cpio, size_t *datasize)
{
    const struct cpio_reader_st **readerp = cpio_reader_list;
    static char pathname[PATH_MAX] = { '\0', };
    size_t filenamesize = 0;
    uint8_t header[256];        /* Enough space for any CPIO header */

    /* If we've reached the end of the archive, we insist on eof */
    if (cpio->archive_eof)
        cpio->eof = 1;

    if (cpio->eof || cpio->error)
        return 0;

    if (cpio->state == CPIO_IN_FILE) {
        cpio->headeroffset += cpio->rel_dataoffset + cpio->datasize_aligned;
        fseek(cpio->file, cpio->headeroffset, SEEK_SET);
        cpio->rel_filenameoffset = cpio->rel_dataoffset = cpio->cur_readoffset =
            cpio->datasize_aligned = 0;
        cpio->state = CPIO_AT_HEADER;
    }

    /* 6 bytes is enough to contain the magic number */
    if (fread(header, 6, 1, cpio->file) == 0) {
        cpio->error = ferror(cpio->file);
        cpio->eof = feof(cpio->file);
        return NULL;
    }

    while (*readerp != NULL
           && (cpio->rel_filenameoffset = (*readerp)->headersize(header)) == 0)
        readerp++;
    cpio->reader = *readerp;

    if (cpio->reader == NULL) {
        cpio->error = 1;
        return NULL;
    }

    if (cpio->reader->filenamesize == NULL) {
        cpio->error = 1;
        return NULL;
    }

    if (fread(header + 6, cpio->rel_filenameoffset - 6, 1, cpio->file) == 0) {
        cpio->error = ferror(cpio->file);
        cpio->eof = feof(cpio->file);
        return NULL;
    }

    filenamesize = cpio->reader->filenamesize(header);
    *datasize = cpio->datasize = cpio->reader->datasize(header);

    cpio->rel_dataoffset =
        ((cpio->rel_filenameoffset + filenamesize + cpio->reader->align - 1)
         / cpio->reader->align)
        * cpio->reader->align;
    cpio->datasize_aligned =
        ((*datasize + cpio->reader->align - 1) / cpio->reader->align)
        * cpio->reader->align;

    if (fread(pathname, cpio->rel_dataoffset - cpio->rel_filenameoffset, 1,
              cpio->file) == 0) {
        cpio->error = ferror(cpio->file);
        cpio->eof = feof(cpio->file);
        return NULL;
    }

    if (strcmp(pathname, "TRAILER!!!") == 0) {
        cpio->eof = cpio->archive_eof = 1;
        return NULL;
    }

    cpio->cur_readoffset = 0;
    cpio->state = CPIO_IN_FILE;

    return pathname;
}

size_t cpio_read(CPIO *cpio, void *ptr, size_t size)
{
    if (cpio->eof || cpio->error)
        return 0;
    if (cpio->cur_readoffset == cpio->datasize) {
        cpio->eof = 1;
        return 0;
    }
    if (cpio->state == CPIO_AT_HEADER) {
        cpio->error = 1;
        return 0;
    }

    if (cpio->cur_readoffset + size > cpio->datasize)
        size = cpio->datasize - cpio->cur_readoffset;
    if (fread(ptr, size, 1, cpio->file) == 0) {
        cpio->error = ferror(cpio->file);
        cpio->eof = feof(cpio->file);
        return 0;
    }
    cpio->cur_readoffset += size;
    return size;
}

int cpio_eof(CPIO *cpio)
{
    return cpio->eof;
}

int cpio_error(CPIO *cpio)
{
    return cpio->error;
}

void cpio_clearerr(CPIO *cpio)
{
    cpio->error = cpio->eof = 0;
}

int cpio_close(CPIO *cpio)
{
    FILE *f = cpio->file;
    OPENSSL_free(cpio);
    return fclose(f) == 0;
}
