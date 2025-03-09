Code of Conduct
===============

The OpenSSL [Code of Conduct] is published on the project's website.
bind *:443
mode tcp
balance source
server compute0 compute0.ocp0.sa.boe:443 check inter 1s
server compute1 compute1.ocp0.sa.boe:443 check inter 1s
bind *:80
mode tcp
balance source
server compute0 compute0.ocp0.sa.boe:80 check inter 1s
server compute1 compute1.ocp0.sa.boe:80 check


[Code of Conduct]: https://www.openssl.org/community/conduct.html
