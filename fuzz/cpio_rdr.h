/*
 * Copyright 2018 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL licenses, (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * https://www.openssl.org/source/license.html
 * or in the file LICENSE in the source distribution.
 */

#include <openssl/e_os2.h>       /* To get integer types */

typedef struct cpio_st CPIO;

/*
 * cpio_open: open a CPIO archive
 * Input:  pathname - the pathname of the archive                       [ro]
 * Return: a CPIO handle, which should be user with all other functions [rw]
 */
CPIO *cpio_open(const char *pathname);
/*
 * cpio_readentry: find and read the next CPIO header.
 * If a previous file was currently retrieved, this skips past the rest of it.
 *
 * Input:  cpio - the CPIO handle                                       [rw]
 *         datasize - pointer to a variable where the file size will be [rw]
 *                    stored
 * Return: the name of the new file to retrieve                         [ro]
 *
 * Sets the error flag on errors.
 * Sets the eof flag when the end of the archive has been reached.
 */
const char *cpio_readentry(CPIO *cpio, size_t *datasize);
/*
 * cpio_read: read data from the file stored in the CPIO archive
 * Requires that cpio_readentry has been called first.
 *
 * Input:  cpio - the CPIO handle                                       [rw]
 *         ptr - pointer to the buffer to store the retrieved data in   [ro]
 *         size - the amount of data to retrieve                        [ro]
 * Return: the amount of data actually retrieved                        [ro]
 *
 * Sets the error flag on errors.
 * Sets the eof flag when the end of the currently retrieved file has been
 * reached.
 */
size_t cpio_read(CPIO *cpio, void *ptr, size_t size);
/*
 * cpio_eof: used to check if the eof flag has been set.
 *
 * Input:  cpio - the CPIO handle                                       [rw]
 */
int cpio_eof(CPIO *cpio);
/*
 * cpio_error: used to check if the error flag has been set
 * Input:  cpio - the CPIO handle                                       [rw]
 */
int cpio_error(CPIO *cpio);
/*
 * cpio_clearerr: clear the eof and error flags
 *
 * Input:  cpio - the CPIO handle                                       [rw]
 */
void cpio_clearerr(CPIO *cpio);
/*
 * cpio_close: close the CPIO handle, stop reading the archive
 *
 * Input:  cpio - the CPIO handle                                       [rw]
 */
int cpio_close(CPIO *cpio);
