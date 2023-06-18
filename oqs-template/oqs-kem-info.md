## Note: As oqs-openssl111 is phased out, please rely on the new iteration of this information at https://github.com/open-quantum-safe/oqs-provider/blob/main/oqs-template/oqs-kem-info.md

| Family         | Implementation Version   | Variant        |   NIST round |   Claimed NIST Level | Code Point   | Hybrid Elliptic Curve (if any)   |
|:---------------|:-------------------------|:---------------|-------------:|---------------------:|:-------------|:---------------------------------|
| BIKE           | 5.1                      | bikel1         |            4 |                    1 | 0x0241       |                                  |
| BIKE           | 5.1                      | bikel1         |            4 |                    1 | 0x2F41       | secp256_r1                       |
| BIKE           | 5.1                      | bikel1         |            4 |                    1 | 0x2FAE       | x25519                           |
| BIKE           | 5.1                      | bikel3         |            4 |                    3 | 0x0242       |                                  |
| BIKE           | 5.1                      | bikel3         |            4 |                    3 | 0x2F42       | secp384_r1                       |
| BIKE           | 5.1                      | bikel3         |            4 |                    3 | 0x2FAF       | x448                             |
| BIKE           | 5.1                      | bikel5         |            4 |                    5 | 0x0243       |                                  |
| BIKE           | 5.1                      | bikel5         |            4 |                    5 | 0x2F43       | secp521_r1                       |
| BIKE           | NIST Round 3 submission  | bikel1         |            3 |                    1 | 0x0238       |                                  |
| BIKE           | NIST Round 3 submission  | bikel1         |            3 |                    1 | 0x2F37       | x25519                           |
| BIKE           | NIST Round 3 submission  | bikel1         |            3 |                    1 | 0x2F38       | secp256_r1                       |
| BIKE           | NIST Round 3 submission  | bikel3         |            3 |                    3 | 0x023B       |                                  |
| BIKE           | NIST Round 3 submission  | bikel3         |            3 |                    3 | 0x2F3B       | secp384_r1                       |
| CRYSTALS-Kyber | NIST Round 2 submission  | kyber1024      |            2 |                    5 | 0x0211       |                                  |
| CRYSTALS-Kyber | NIST Round 2 submission  | kyber1024      |            2 |                    5 | 0x2F11       | secp521_r1                       |
| CRYSTALS-Kyber | NIST Round 2 submission  | kyber512       |            2 |                    1 | 0x020F       |                                  |
| CRYSTALS-Kyber | NIST Round 2 submission  | kyber512       |            2 |                    1 | 0x2F0F       | secp256_r1                       |
| CRYSTALS-Kyber | NIST Round 2 submission  | kyber512       |            2 |                    1 | 0x2F26       | x25519                           |
| CRYSTALS-Kyber | NIST Round 2 submission  | kyber768       |            2 |                    3 | 0x0210       |                                  |
| CRYSTALS-Kyber | NIST Round 2 submission  | kyber768       |            2 |                    3 | 0x2F10       | secp384_r1                       |
| CRYSTALS-Kyber | NIST Round 3 submission  | kyber1024      |            3 |                    5 | 0x023D       |                                  |
| CRYSTALS-Kyber | NIST Round 3 submission  | kyber1024      |            3 |                    5 | 0x2F3D       | secp521_r1                       |
| CRYSTALS-Kyber | NIST Round 3 submission  | kyber512       |            3 |                    1 | 0x023A       |                                  |
| CRYSTALS-Kyber | NIST Round 3 submission  | kyber512       |            3 |                    1 | 0x2F39       | x25519                           |
| CRYSTALS-Kyber | NIST Round 3 submission  | kyber512       |            3 |                    1 | 0x2F3A       | secp256_r1                       |
| CRYSTALS-Kyber | NIST Round 3 submission  | kyber768       |            3 |                    3 | 0x023C       |                                  |
| CRYSTALS-Kyber | NIST Round 3 submission  | kyber768       |            3 |                    3 | 0x2F3C       | secp384_r1                       |
| CRYSTALS-Kyber | NIST Round 3 submission  | kyber768       |            3 |                    3 | 0x2F90       | x448                             |
| FrodoKEM       | NIST Round 3 submission  | frodo1344aes   |            3 |                    5 | 0x0204       |                                  |
| FrodoKEM       | NIST Round 3 submission  | frodo1344aes   |            3 |                    5 | 0x2F04       | secp521_r1                       |
| FrodoKEM       | NIST Round 3 submission  | frodo1344shake |            3 |                    5 | 0x0205       |                                  |
| FrodoKEM       | NIST Round 3 submission  | frodo1344shake |            3 |                    5 | 0x2F05       | secp521_r1                       |
| FrodoKEM       | NIST Round 3 submission  | frodo640aes    |            3 |                    1 | 0x0200       |                                  |
| FrodoKEM       | NIST Round 3 submission  | frodo640aes    |            3 |                    1 | 0x2F00       | secp256_r1                       |
| FrodoKEM       | NIST Round 3 submission  | frodo640aes    |            3 |                    1 | 0x2F80       | x25519                           |
| FrodoKEM       | NIST Round 3 submission  | frodo640shake  |            3 |                    1 | 0x0201       |                                  |
| FrodoKEM       | NIST Round 3 submission  | frodo640shake  |            3 |                    1 | 0x2F01       | secp256_r1                       |
| FrodoKEM       | NIST Round 3 submission  | frodo640shake  |            3 |                    1 | 0x2F81       | x25519                           |
| FrodoKEM       | NIST Round 3 submission  | frodo976aes    |            3 |                    3 | 0x0202       |                                  |
| FrodoKEM       | NIST Round 3 submission  | frodo976aes    |            3 |                    3 | 0x2F02       | secp384_r1                       |
| FrodoKEM       | NIST Round 3 submission  | frodo976aes    |            3 |                    3 | 0x2F82       | x448                             |
| FrodoKEM       | NIST Round 3 submission  | frodo976shake  |            3 |                    3 | 0x0203       |                                  |
| FrodoKEM       | NIST Round 3 submission  | frodo976shake  |            3 |                    3 | 0x2F03       | secp384_r1                       |
| FrodoKEM       | NIST Round 3 submission  | frodo976shake  |            3 |                    3 | 0x2F83       | x448                             |
| HQC            | NIST Round 3 submission  | hqc128         |            3 |                    1 | 0x022C       |                                  |
| HQC            | NIST Round 3 submission  | hqc128         |            3 |                    1 | 0x2F2C       | secp256_r1                       |
| HQC            | NIST Round 3 submission  | hqc128         |            3 |                    1 | 0x2FAC       | x25519                           |
| HQC            | NIST Round 3 submission  | hqc192         |            3 |                    3 | 0x022D       |                                  |
| HQC            | NIST Round 3 submission  | hqc192         |            3 |                    3 | 0x2F2D       | secp384_r1                       |
| HQC            | NIST Round 3 submission  | hqc192         |            3 |                    3 | 0x2FAD       | x448                             |
| HQC            | NIST Round 3 submission  | hqc256         |            3 |                    5 | 0x022E       |                                  |
| HQC            | NIST Round 3 submission  | hqc256         |            3 |                    5 | 0x2F2E       | secp521_r1                       |
