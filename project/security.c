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
uint16_t transcript_len = 0; // needs to be global

uint8_t ts[4096] = {0};
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
        state_sec = CLIENT_SERVER_HELLO_AWAIT;
        return len;
        break;
    }
    case SERVER_SERVER_HELLO_SEND: {
        print("SEND SERVER HELLO");
        server_hello = create_tlv(SERVER_HELLO); // order according to project page *should* be Client-Hello, Nonce, Cert, Public Key, with sig following up all 4
        
        // generate nonce here
        tlv* nn = create_tlv(NONCE); // create a nonce TLV
        uint8_t nonce[NONCE_SIZE];
        generate_nonce(nonce, NONCE_SIZE);
        add_val(nn, nonce, NONCE_SIZE);
        //add_tlv(server_hello, nn); // add nonce to server hello packet  moved to *after serialization*

        load_certificate("server_cert.bin");
        tlv* cert = deserialize_tlv(certificate, cert_size); // since cert is loaded from the .bin, no need to create a new tlv?
        // tlv* cert = create_tlv(CERTIFICATE);
        // add_val(cert, certificate, cert_size);
        // add_tlv(server_hello, cert);
       
        // priv key and signature
        generate_private_key();
        derive_public_key();
        // save ephemeral key
        EVP_PKEY* ephemeral_key = get_private_key();
        tlv* pk = create_tlv(PUBLIC_KEY);
        add_val(pk, public_key, pub_key_size);
        // Grab public key extern values and create tlv for them to append
        // add_tlv(server_hello, pk);

        uint8_t to_sign[4096];
        uint16_t to_sign_len = 0;
        
        memcpy(to_sign + to_sign_len, ts, ts_len); // supposed to account for the recved client-hello
        to_sign_len += ts_len;

        to_sign_len += serialize_tlv(to_sign + to_sign_len, nn);
        to_sign_len += serialize_tlv(to_sign + to_sign_len, cert);
        to_sign_len += serialize_tlv(to_sign + to_sign_len, pk);

        // moved add tlvs here
        add_tlv(server_hello, nn);
        add_tlv(server_hello, cert);
        add_tlv(server_hello, pk);

        // sign current transcript
        load_private_key("server_key.bin");
        uint8_t handshake_signature_bytes[128];
        size_t sig_len = sign(handshake_signature_bytes, to_sign, to_sign_len);
        // attach handshake
        tlv* sig = create_tlv(HANDSHAKE_SIGNATURE);
        add_val(sig, handshake_signature_bytes, sig_len);
        add_tlv(server_hello, sig);

        // serialize server_hello
        uint16_t len = serialize_tlv(buf, server_hello);

        // create salt for symmetric key derivation
        uint8_t salt_buf[4096];
        uint16_t salt_len = 0;

        memcpy(salt_buf, ts, ts_len); // client hello
        salt_len += ts_len;

        memcpy(salt_buf + salt_len, buf, len); // server hello
        salt_len += len;

        // append server_hello to transcript (ts)
        memcpy(ts + ts_len, buf, len);
        ts_len += len;
        transcript_len = ts_len;

        // derive secrets and keys
        set_private_key(ephemeral_key);
        derive_secret();
        derive_keys(salt_buf, salt_len);

        free_tlv(server_hello);
        state_sec = SERVER_FINISHED_AWAIT;

        return len;
        break;
    }
    case CLIENT_FINISHED_SEND: {
        print("SEND FINISHED");

        uint8_t digest[MAC_SIZE];
        hmac(digest, ts, transcript_len);

        tlv* finished = create_tlv(FINISHED);
        tlv* transcript = create_tlv(TRANSCRIPT);
        add_val(transcript, digest, MAC_SIZE);
        add_tlv(finished, transcript);

        uint16_t len = serialize_tlv(buf, finished);
        free_tlv(finished);
        state_sec = DATA_STATE;
        return len;
        break;
    }
    case DATA_STATE: {
        uint8_t plaintext[943];
        ssize_t plaintext_len = read(STDIN_FILENO, plaintext, 943);
        if (plaintext_len <= 0)
            return 0;

        uint8_t iv[IV_SIZE];
        uint8_t cipher[2000];

        size_t cipher_len = encrypt_data(iv, cipher, plaintext, plaintext_len);

        tlv* iv_tlv = create_tlv(IV);
        add_val(iv_tlv, iv, IV_SIZE);

        tlv* cipher_tlv = create_tlv(CIPHERTEXT);
        add_val(cipher_tlv, cipher, cipher_len);

        uint8_t mac_data[4096];
        uint16_t mac_data_len = 0;
        uint16_t iv_len = serialize_tlv(mac_data, iv_tlv);
        mac_data_len += iv_len;
        uint16_t ct_len = serialize_tlv(mac_data + mac_data_len, cipher_tlv);
        mac_data_len += ct_len;

        uint8_t mac[MAC_SIZE];
        hmac(mac, mac_data, mac_data_len);
        if (inc_mac) mac[0] ^= 0xFF;

        tlv* mac_tlv = create_tlv(MAC);
        add_val(mac_tlv, mac, MAC_SIZE);

        tlv* data = create_tlv(DATA);
        add_tlv(data, iv_tlv);
        add_tlv(data, cipher_tlv);
        add_tlv(data, mac_tlv);

        uint16_t len = serialize_tlv(buf, data);
        free_tlv(data);
        return len;
        break;
    }
    default:
        return 0;
        break;
    }
}

void output_sec(uint8_t* buf, size_t length) {
    switch (state_sec) {
    case SERVER_CLIENT_HELLO_AWAIT: {
        client_hello = deserialize_tlv(buf, length);
        if(client_hello == NULL){
            return(6); // return an error
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
        tlv* server_hello = deserialize_tlv(buf, length);
        if (server_hello == NULL || server_hello->type != SERVER_HELLO) exit(6);

        //load_peer_public_key();
        load_ca_public_key("ca_public_key.bin");

        //verify handshake sig and cert
        tlv* cert = get_tlv(server_hello, CERTIFICATE);
        if(!cert) exit(6);
        tlv* sig = get_tlv(cert, SIGNATURE);
        tlv* dns = get_tlv(cert, DNS_NAME);
        tlv* pk = get_tlv(cert, PUBLIC_KEY);
        tlv* lifetime = get_tlv(cert, LIFETIME);

        uint8_t cert_data[4096];
        uint16_t cert_data_len = 0;
        cert_data_len += serialize_tlv(cert_data + cert_data_len, dns);
        cert_data_len += serialize_tlv(cert_data + cert_data_len, pk);
        cert_data_len += serialize_tlv(cert_data + cert_data_len, lifetime);

        load_ca_public_key("ca_public_key.bin"); 
        if (!verify(sig->val, sig->length, cert_data, cert_data_len, ec_ca_public_key)) { // verify pub key
            exit(1);
        }

        //verify();
        int cert_valid = verify(sig->val, sig->length, cert_data, cert_data_len, ec_ca_public_key);
        if (!cert_valid) {
            exit(1);
        }
        if (dns->length < strlen(hostname) ||
            strncmp((char*)dns->val, hostname, strlen(hostname)) != 0) {
            exit(2);
        }

        memcpy(ts + ts_len, buf, length);
        ts_len += length;
        transcript_len = ts_len; // saved for later

        tlv* server_nonce = get_tlv(server_hello, NONCE);
        tlv* server_cert = get_tlv(server_hello, CERTIFICATE);
        tlv* server_pk = get_tlv(server_hello, PUBLIC_KEY);
        tlv* handshake_sig = get_tlv(server_hello, HANDSHAKE_SIGNATURE);

        uint8_t to_verify[4096];
        uint16_t to_verify_len = 0;
        memcpy(to_verify, ts, ts_len - length);
        to_verify_len += ts_len - length;
        to_verify_len += serialize_tlv(to_verify + to_verify_len, server_nonce);
        to_verify_len += serialize_tlv(to_verify + to_verify_len, server_cert);
        to_verify_len += serialize_tlv(to_verify + to_verify_len, server_pk);

        load_peer_public_key(pk->val, pk->length);

        int sig_valid = verify(handshake_sig->val, handshake_sig->length, to_verify, to_verify_len, ec_peer_public_key);
        if (!sig_valid) {
            exit(3);
        }

        load_peer_public_key(server_pk->val, server_pk->length);

        uint8_t salt_buf[4096];
        uint16_t salt_len = 0;
        memcpy(salt_buf, ts, ts_len - length);
        salt_len += ts_len - length;
        memcpy(salt_buf + salt_len, buf, length);
        salt_len += length;

        derive_secret();
        derive_keys(salt_buf, salt_len);

        state_sec = CLIENT_FINISHED_SEND;
        break;
    }
    case SERVER_FINISHED_AWAIT: {
        print("RECV FINISHED");

        tlv* finished = deserialize_tlv(buf, length);
        tlv* transcript = get_tlv(finished, TRANSCRIPT);

        uint8_t digest[MAC_SIZE];
        hmac(digest, ts, transcript_len);

        if (memcmp(digest, transcript->val, MAC_SIZE) != 0) {
            exit(4);
        }

        free_tlv(finished);
        state_sec = DATA_STATE;
        break;
    }
    case DATA_STATE: {
        tlv* data = deserialize_tlv(buf, length);
        tlv* iv_tlv = get_tlv(data, IV);
        tlv* cipher_tlv = get_tlv(data, CIPHERTEXT);
        tlv* mac_tlv = get_tlv(data, MAC);

        uint8_t mac_data[4096];
        uint16_t mac_data_len = 0;
        uint16_t iv_len = serialize_tlv(mac_data, iv_tlv);
        mac_data_len += iv_len;
        uint16_t ct_len = serialize_tlv(mac_data + mac_data_len, cipher_tlv);
        mac_data_len += ct_len;

        uint8_t mac[MAC_SIZE];
        hmac(mac, mac_data, mac_data_len);

        if (memcmp(mac, mac_tlv->val, MAC_SIZE) != 0) {
            exit(5);
        }

        uint8_t plaintext[2000];
        size_t plaintext_len = decrypt_cipher(plaintext, cipher_tlv->val, cipher_tlv->length, iv_tlv->val);

        write(STDOUT_FILENO, plaintext, plaintext_len);

        free_tlv(data);
        break;
    }
    default:
        break;
    }
}


