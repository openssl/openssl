$!
$!  SSL$EXAMPLES_SETUP.COM --  
$! 
$! This command procedure is actually a template that will show 
$! the commands necessary to create certificates and keys for the example
$! programs.  
$!
$! Also included in this file are the necessary options to enter into the
$! SSL$CERT_TOOL.COM to create the necessary certificates and keys to the
$! example programs.  The SSL$CERT_TOOL.COM is found in SSL$COM.  See the
$! documenation for more information about the SSL$CERT_TOOL.COM.
$!
$! 1. Create CA certificate - option 5 in SSL$CERT_TOOL.COM.
$!    This will create a key in one file and a certificate in
$!    another file.
$!
$! 2. Make 2 copies of CA certificate created in step #1.
$!    One should be called server_ca.crt and the other called 
$!    client_ca.crt as these are the filenames defined in the
$!    example programs.  You will have to exit the SSL$CERT_TOOL.COM 
$!    procedure to do this operation.
$!
$! 3. Create a server certificate signing request - option 3 in SSL$CERT_TOOL.COM.
$!    The Common Name should be the TCP/IP hostname of the server system.
$!
$! 4. Sign server certificate signing request - option 6 in SSL$CERT_TOOL.COM
$!    Use the CA certificate, server_ca.crt, created in step #1 to sign the request 
$!    created in step #3.  This will create a key file, which should be named 
$!    server.key, and a certificate file, which should be named server.crt.
$!    These are the names as they are defined in example programs.
$!
$! 5. Create a client certificate signing request - option 3 in SSL$CERT_TOOL.COM.
$!
$! 6. Sign client certificate signing request - option 6 in SSL$CERT_TOOL.COM
$!    Use the CA certificate, client_ca.crt, created in step #1 to sign the request 
$!    created in step #5.  This will create a key file, which should be named 
$!    client.key, and a certificate file, which should be named client.crt.
$!    These are the names as they are defined in example programs.
$!
$! 7. These certificates and keys should reside in the same directory as
$!    the example programs.
$!
$!
$!
$!
$! The commands have been changed to use generic data as 
$! input.  To use these commands, one will have to substitute 
$! the generic data with data specific to their site.  
$! For example, yourcountry could be change to US.  It is 
$! assumed that the SSL startup file, SYS$STARTUP:SSL$STARTUP.COM, 
$! and the SSL$COM:SSL$UTILS.COM procedures have been executed.
$!
$! Set up some random data.
$!
$! $ show system/full/output=randfile.
$!
$!
$! Check to make sure the SERIAL and INDEX files exist.
$! If they don't, create them.
$!
$! $ if f$search ("SSL$PRIVATE:SERIAL.TXT") .eqs. ""
$! $ then
$! $   CREATE SSL$PRIVATE:SERIAL.TXT
$! 01
$! $ endif
$!
$! $ if f$search ("SSL$PRIVATE:INDEX.TXT") .eqs. ""
$! $ then
$! $   CREATE SSL$PRIVATE:INDEX.TXT
$! $ endif
$!
$! Create the CA certificate.
$!
$! $ define/user sys$command sys$input
$! $ openssl req -config ssl$root:[000000]openssl-vms.cnf -new -x509 -days 1825 -keyout ca.key -out ca.crt
$! yourpassword
$! yourpassword
$! yourcountry
$! yourstate
$! yourcity
$! yourcompany
$! yourdepartment
$! your Certificate Authority certificate
$! firstname.lastname@yourcompany.com
$! $!
$! $!
$! $! Create the server certificate request.
$! $!
$! $!   Note : There is no way to use the value of a
$! $!          symbol when you are using the value of
$! $!          symbol as input, as we do below.  To get
$! $!          around, we create a .COM on the fly and
$! $!          execute the created .COm file to create
$! $!          the server certificate.  What a pain!
$! $!
$! $ hostname = f$trnlnm("tcpip$inet_host")
$! $ domain = f$trnlnm("tcpip$inet_domain")
$! $ server_name = hostname + "." + domain"
$! $!
$! $ open/write s_com create_s_cert.com
$! $! 
$! $ write s_com "$!"
$! $ write s_com "$ define/user sys$command sys$input
$! $ write s_com "$ openssl req -new -nodes -config ssl$root:[000000]openssl-vms.cnf -keyout server.key -out server.csr"
$! $ write s_com "yourcountry"
$! $ write s_com "yourstate"
$! $ write s_com "yourcity"
$! $ write s_com "yourcompany"
$! $ write s_com "yourdepartment"
$! $ write s_com "''server_name'"
$! $ write s_com "firstname.lastname@yourcompany.com"
$! $ write s_com ""
$! $ write s_com ""
$! $!
$! $ close s_com
$! $ @create_s_cert
$! $ delete create_s_cert.com;
$! $!
$! $!
$! $! Now, sign the server certificate ...
$! $!
$! $ define/user sys$command sys$input
$! $ openssl ca -config ssl$root:[000000]openssl-vms.cnf -cert ca.crt -keyfile ca.key -out server.crt -infiles server.csr
$! yourpassword
$! Y
$! Y
$! $!
$! $!
$! $! Create the client certificate request.
$! $!
$! $ define/user sys$command sys$input
$! $ openssl req -new -nodes -config ssl$root:[000000]openssl-vms.cnf -keyout client.key -out client.csr
$! yourcountry
$! yourstate
$! yourcity
$! yourcompany
$! yourdepartment
$! yourname
$! firstname.lastname@yourcompany.com
$! 
$! 
$! $!
$! $!
$! $! Now, sign the client certificate ...
$! $!
$! $ define/user sys$command sys$input
$! $ openssl ca -config ssl$root:[000000]openssl-vms.cnf -cert ca.crt -keyfile ca.key -out client.crt -infiles client.csr
$! yourpassword
$! Y
$! Y
$! $!
$! $! Let's view the CA certificate.
$! $!
$! $ openssl x509 -noout -text -in ca.crt
$! $!
$! $!
$! $! Let's view the Server Certificate Request.
$! $!
$! $ openssl req -noout -text -in server.csr
$! $!
$! $! Let's view the Server Certificate.
$! $!
$! $ openssl x509 -noout -text -in server.crt
$! $!
$! $! Let's view the Client Certificate Request.
$! $!
$! $ openssl req -noout -text -in client.csr
$! $!
$! $! Let's view the Client Certificate.
$! $!
$! $ openssl x509 -noout -text -in client.crt
$! $!
$! $!
$! $exit
