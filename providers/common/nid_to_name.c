/*
 * Copyright 2019 The Opentls Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.opentls.org/source/license.html
 */

#include <opentls/objects.h>
#include "prov/providercommon.h"

/*
 * The FIPS provider has its own version of this in fipsprov.c because it does
 * not have OBJ_nid2sn();
 */
const char *otls_prov_util_nid_to_name(int nid)
{
   return OBJ_nid2sn(nid);
}

