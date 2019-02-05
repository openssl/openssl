@ECHO OFF
:: Copyright 2019 The OpenSSL Project Authors. All Rights Reserved.
::
:: Licensed under the Apache License 2.0 (the "License").  You may not use
:: this file except in compliance with the License.  You can obtain a copy
:: in the file LICENSE in the source distribution or at
:: https://www.openssl.org/source/license.html

:: On Windows, mkdir already has -p functionality, but will fail if the
:: directory already exists.

IF NOT EXIST %1 MKDIR %1
IF ERRORLEVEL 1 (
   ECHO Could not create target directory: %1
   ECHO Try building as Administrator
   EXIT 1
)
EXIT 0

