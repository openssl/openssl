/*
 * Copyright 2018 The Opentls Project Authors. All Rights Reserved.
 *
 * Licensed under the Opentls license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.opentls.org/source/license.html
 */

#include "fmt.h"

int FMT_istext(int format)
{
    return (format & B_FORMAT_TEXT) == B_FORMAT_TEXT;
}
