# OpenSSL DTLS Listener Server/Client

This project implements a simple echo application utilizing DTLS SSL Listener.

It is a console application, with command line parameters determining the mode
of operation (client or server). Start it with no parameters to see usage.

The server code utilizes the SSL Listener to setup a DTLS Server object that
can handle multiple client connections using a thread-per-connection model.
Each accepted connection is handled in its own dedicated thread, following
the pattern established in `test/dtls_multithread_test.c`.

The client will send application data to the server and the server will simply
respond to the client with an echo of that data.

## Features

- Up to 10 concurrent DTLS client connections (MAX_CONNECTIONS)
- Thread-per-connection architecture using OpenSSL's internal thread APIs
- Non-blocking I/O using SSL_poll() within each connection thread
- Supports both DTLS 1.2 (HelloVerifyRequest) and DTLS 1.3 (HelloRetryRequest)
- Client option to specify DTLS protocol version (dtls12 or dtls13)
- Active shutdown signaling for clean thread termination
- Server-wide shutdown via "killall" command

## Limitations

- Maximum 10 concurrent client connections (defined by MAX_CONNECTIONS)
- Additional connection attempts while at capacity will be rejected with an
  error message printed to the server console

## The code demonstrates

- DTLS Server using SSL Listener APIs to establish Connections
- DTLS Server validating Clients via HRR/HVR
- Thread-per-connection model for handling multiple clients
- Clients sending data to an established Server
- Server utilizing SSL_poll() within each thread for read readiness
- Server sending data to an established Client
- Client-side DTLS version selection via command-line argument
- Using SSL_CTX_set_min_proto_version() and SSL_CTX_set_max_proto_version()
- Active thread shutdown via signaling mechanism
- Graceful server shutdown with client disconnection

## Running

### Start the Server

```console
./dtlslistenerecho s
```

### Connect Multiple Clients (in separate terminals)

You can connect up to 10 clients simultaneously:

```console
./dtlslistenerecho c localhost
./dtlslistenerecho c localhost
./dtlslistenerecho c localhost
```

Each client can send messages independently and receive echoes.

### Specify DTLS Protocol Version

You can optionally specify the DTLS protocol version for the client:

```console
# Connect using DTLS 1.2
./dtlslistenerecho c localhost dtls12

# Connect using DTLS 1.3
./dtlslistenerecho c localhost dtls13

# Connect using default (negotiates highest available)
./dtlslistenerecho c localhost
```

## Special Commands

- Type "kill" in a client to disconnect that client only (server continues running)
- Type "killall" in a client to disconnect all clients and shutdown the server gracefully

When "killall" is received:
1. The server sets a shutdown flag
2. All connection threads are signaled to terminate
3. Each thread completes its current operation and exits cleanly
4. The server closes the listener and exits

The cert.pem and key.pem files included are self signed certificates with the
"Common Name" of 'localhost'.

Best to create the 'pem' files using an actual hostname.
