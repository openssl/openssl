This directory contains the algorithm life-cycle diagram sources.

The canonical life-cycles are in the spreadsheet.

The various .dot files are graph descriptions for the
[GraphViz](https://www.graphviz.org/) tool.  These omit edges and should
be used for guidance only.

To generate the rendered images, you need to install:
``` sh
sudo apt install graphviz cpanminus
sudo cpanm Graph::Easy
```

Running `make` will produce a number of `.txt` and `.png` files.
These are the rendered `.dot` files.  The `.txt` files require
additional editing before they can be added to the manual pages in
`internal/man7/life_cycle-*.pod`.

## diagrams

![cipher hosted on pointillism.io](https://pointillism.io/openssl/openssl/blob/master/doc/life-cycles/cipher.dot)

![digest hosted on pointillism.io](https://pointillism.io/openssl/openssl/blob/master/doc/life-cycles/digest.dot)

![kdf hosted on pointillism.io](https://pointillism.io/openssl/openssl/blob/master/doc/life-cycles/kdf.dot)

![mac hosted on pointillism.io](https://pointillism.io/openssl/openssl/blob/master/doc/life-cycles/mac.dot)

![pkey hosted on pointillism.io](https://pointillism.io/openssl/openssl/blob/master/doc/life-cycles/pkey.dot)

![rand hosted on pointillism.io](https://pointillism.io/openssl/openssl/blob/master/doc/life-cycles/rand.dot)

![cipher hosted on pointillism.io](https://pointillism.io/openssl/openssl/blob/master/doc/life-cycles/cipher.dot)
