#!/usr/bin/env python3
"""RFC 9925 unsigned certificate. PEM in on stdin, PEM out on stdout."""
import sys
from functools import reduce

from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding

c = x509.load_pem_x509_certificate(sys.stdin.buffer.read())
b = reduce(
    lambda b, e: b.add_extension(e.value, e.critical),
    c.extensions,
    x509.CertificateBuilder()
    .subject_name(c.subject)
    .issuer_name(c.issuer)
    .serial_number(c.serial_number)
    .public_key(c.public_key())
    .not_valid_before(c.not_valid_before_utc)
    .not_valid_after(c.not_valid_after_utc),
)
sys.stdout.buffer.write(b.create_unsigned().public_bytes(Encoding.PEM))
