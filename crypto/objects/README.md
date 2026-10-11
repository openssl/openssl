objects.txt
===========

`objects.txt` lists the built-in ASN.1 objects.  The build generates
`include/openssl/obj_mac.h`, `crypto/objects/obj_dat.h` and
`crypto/objects/obj_xref.h` from it.

Each line has five fields separated by colons, with no spaces around
them:

    NID:NAME:OID:SN:LN

- `NID` is the object's number, `NID_<NAME>`.
- `NAME` is its C name.  The macros for the object are `SN_<NAME>`,
  `LN_<NAME>`, `NID_<NAME>` and `OBJ_<NAME>`.
- `OID` is the object identifier in dotted decimal.
- `SN` is the short name.
- `LN` is the long name.

An empty field means the object has none.  Every line has all five
fields, and only `LN` may contain spaces.  Lines starting with `#` are
comments.

    1:rsadsi:1.2.840.113549:rsadsi:RSA Data Security, Inc.
    6:rsaEncryption:1.2.840.113549.1.1.1::rsaEncryption

The numbered lines are in NID order, each NID one more than the one
before.

A removed object keeps its NID, with `removed` in place of the OID and
no names:

    124:rle_compression:removed::

An alias defines only `OBJ_<NAME>`, has no NID, and may be anywhere in
the file:

    alias:pkcs12:1.2.840.113549.1.12::

Adding an object
----------------

Append a line at the end of the file, with the NID one more than the
NID on the last line.

A NID is part of the API: applications compile it in, and it is the
same on every branch the object is backported to.  An existing line's
NID never changes, and a removed object's NID is never reused.

The build fails with the file and line number on a NID out of
sequence, a name, short name or long name that is already used, a
malformed OID, or a line without five fields.
