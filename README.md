CS118 Project 3: TLS Security Layer

Overview
This project adds a security layer on top of the Project 2 reliable transport. The implementation lives entirely in security.c and is driven by a state machine across input_sec and output_sec. Most cryptographic operations are handled through the provided libsecurity abstraction layer.

Client Hello

The client generates a nonce and an ephemeral key pair using the provided libsecurity functions. Both are wrapped in TLV structures and nested inside the Client Hello TLV. The serialized Client Hello is cached into a global buffer ts for later use in key derivation and transcript HMAC computation.

Server Hello

On receiving the Client Hello, the server extracts and caches the raw bytes into ts and loads the client's ephemeral public key. It generates its own nonce and ephemeral key pair, deserializes the certificate from server_cert.bin, and signs the concatenation of the received Client Hello, its nonce, certificate, and ephemeral public key using the server private key from server_key.bin. All components are assembled into a Server Hello TLV and serialized. The server then derives the shared secret and session keys using derive_secret and derive_keys, with a salt built from the Client Hello followed by the Server Hello.

Finished

The client verifies the Server Hello in three steps. First it checks the certificate signature against the CA public key from ca_public_key.bin, exiting with status 1 on failure. Then it checks the DNS name in the certificate against the hostname argument using strncmp, being careful to compare against the hostname length rather than the certificate DNS field length to handle trailing null bytes. It exits with status 2 on mismatch. Finally it reconstructs the signed data and verifies the handshake signature using the certificate's public key, exiting with status 3 on failure. After all checks pass, the client derives the shared secret and session keys the same way the server did, then sends a Finished message containing an HMAC digest over the full transcript. The server verifies this digest and exits with status 4 if it doesn't match.

Data Transfer
In the data state, plaintext is read from stdin in chunks up to 943 bytes, which is the maximum that fits within the packet payload limit after accounting for the various TLV headers. Each chunk is encrypted using encrypt_data which also generates a fresh IV. A MAC is then computed over the serialized IV and ciphertext TLVs using hmac. On the receive side the MAC is verified before any decryption takes place, exiting with status 5 on failure.
