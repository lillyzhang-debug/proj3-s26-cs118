#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "consts.h"
#include "io.h"
#include "libsecurity.h"

int state_sec = 0;     // Current state for handshake
char* hostname = NULL; // For client: storing inputted hostname
EVP_PKEY* priv_key = NULL;
tlv* client_hello = NULL;
tlv* server_hello = NULL;

uint8_t ts[1000] = {0};
uint16_t ts_len = 0;

bool inc_mac = false;  // For testing only: send incorrect MACs

void init_sec(int initial_state, char* host, bool bad_mac) {
    state_sec = initial_state;
    hostname = host; // save hostname input
    inc_mac = bad_mac;
    init_io();

    if (state_sec == CLIENT_CLIENT_HELLO_SEND) {
        // do something if client sending hello
    } else if (state_sec == SERVER_CLIENT_HELLO_AWAIT) {
        // do something else if server waiting for hello
    }
}

ssize_t input_sec(uint8_t* buf, size_t max_length) {
    switch (state_sec) {
    case CLIENT_CLIENT_HELLO_SEND: {
        print("SEND CLIENT HELLO");
        client_hello = create_tlv(CLIENT_HELLO); // create TLV packet with CLIENT_HELLO MSG 
        // generate nonce here
        tlv* nn = create_tlv(NONCE); // create a nonce TLV
        uint8_t nonce[NONCE_SIZE];
        generate_nonce(nonce, NONCE_SIZE);

        // append nonce to client hello packet
        add_val(nn, nonce, NONCE_SIZE);
        add_tlv(client_hello, nn); 

        // generate private key
        generate_private_key();
        // derive public key from private key
        derive_public_key();
        // Grab public key extern values and create tlv for them to append
        tlv* pk = create_tlv(PUBLIC_KEY);
        add_val(pk, public_key, pub_key_size);
        add_tlv(client_hello, pk);
        // serialize and cache hello message
        uint16_t len = serialize_tlv(buf, client_hello);
        memcpy(ts, buf, len);
        ts_len = len;
        free_tlv(client_hello);
        state_sec = SERVER_CLIENT_HELLO_AWAIT; // i think this is the right state change
        return len;
    }
    case SERVER_SERVER_HELLO_SEND: {
        print("SEND SERVER HELLO");
        server_hello = create_tlv(SERVER_HELLO);

        // generate nonce here
        tlv* nn = create_tlv(NONCE); // create a nonce TLV
        uint8_t nonce[NONCE_SIZE];
        generate_nonce(nonce, NONCE_SIZE);
        add_val(nn, nonce, NONCE_SIZE);
        add_tlv(server_hello, nn); // add nonce to server hello packet

        // priv key and signature
        load_private_key("server_key.bin"); // pass in the file server_cert.bin as the file name
        // to generate ephemeral key
        generate_private_key();
        derive_public_key();
        tlv* pk = create_tlv(PUBLIC_KEY);
        add_val(pk, public_key, pub_key_size);
        // Grab public key extern values and create tlv for them to append
        add_tlv(server_hello, pk);

        // sign current transcript
        uint8_t handshake_signature_bytes[128];
        size_t sig_len = sign(handshake_signature_bytes, ts, ts_len);
        // attach handshake
        tlv* sig = create_tlv(HANDSHAKE_SIGNATURE);
        add_val(sig, handshake_signature_bytes, sig_len);
        add_tlv(server_hello, sig);

        // serialize
        uint16_t len = serialize_tlv(buf, server_hello);

        // append server_hello to transcript (ts)
        memcpy(ts + ts_len, buf, len);
        ts_len += len;

        // derive secrets and keys
        derive_secret();
        derive_keys(ts, ts_len);

        free_tlv(server_hello);
        state_sec = SERVER_FINISHED_AWAIT; 

        return len;
    }
    case CLIENT_FINISHED_SEND: {
        print("SEND FINISHED");
        //hmac();
    }
    case DATA_STATE: {
    }
    default:
        return 0;
    }
}

void output_sec(uint8_t* buf, size_t length) {
    switch (state_sec) {
    case SERVER_CLIENT_HELLO_AWAIT: {
        client_hello = deserialize_tlv(buf, length);
        if(client_hello == NULL){
            return -1; // return an error
        }

        tlv* nn = get_tlv(client_hello, NONCE); // if we recv a client hello generate a nonce.
        if (nn != NULL){
            // cache client hello in transcript
           memcpy(ts, buf, length);
           ts_len = length;

            // extract and load client ephemeral public key
           tlv* pk_node = get_tlv(client_hello, PUBLIC_KEY);
           if(pk_node != NULL && pk_node->val != NULL){
                load_peer_public_key(pk_node->val, pk_node->length);
           }

           // move to next state, if recv server send HELLO
           state_sec = SERVER_SERVER_HELLO_SEND;

           free_tlv(client_hello);
        } else {
            free_tlv(client_hello);
            return;
        }
        break;
    }
    case CLIENT_SERVER_HELLO_AWAIT: {
        // recv serverhello
        //load_peer_public_key();
        //verify handshake sig and cert
        load_ca_public_key("server_cert.bin");
        //verify();
    }
    case SERVER_FINISHED_AWAIT: {
    }
    case DATA_STATE: {
        tlv* data = deserialize_tlv(buf, length);
    }
    default:
        break;
    }
}