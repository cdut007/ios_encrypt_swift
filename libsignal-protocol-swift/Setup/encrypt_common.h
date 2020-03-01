//
//  encrypt_common.h
//  libsignal-protocol-swift iOS
//
//  Created by mac on 2020/3/1.
//  Copyright © 2020 User. All rights reserved.
//

#ifndef encrypt_common_h
#define encrypt_common_h

#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include "signal_protocol.h"

/* Test utility functions */
void print_public_key2(const char *prefix, ec_public_key *key);
void print_buffer2(const char *prefix, signal_buffer *buffer);
void shuffle_buffers2(signal_buffer **array, size_t n);
ec_public_key *create_ec_public_key2(signal_context *context);
ec_private_key *create_ec_private_key2(signal_context *context);

/* Test logging */
void common_log2(int level, const char *message, size_t len, void *user_data);

/* Test crypto provider */
int random_generator2(uint8_t *data, size_t len, void *user_data);
int hmac_sha256_init2(void **hmac_context, const uint8_t *key, size_t key_len, void *user_data);
int hmac_sha256_update2(void *hmac_context, const uint8_t *data, size_t data_len, void *user_data);
int hmac_sha256_final2(void *hmac_context, signal_buffer **output, void *user_data);
void hmac_sha256_cleanup2(void *hmac_context, void *user_data);
int sha512_digest_init2(void **digest_context, void *user_data);
int sha512_digest_update2(void *digest_context, const uint8_t *data, size_t data_len, void *user_data);
int sha512_digest_final2(void *digest_context, signal_buffer **output, void *user_data);
void sha512_digest_cleanup2(void *digest_context, void *user_data);
int whisper_encrypt2(signal_buffer **output,
        int cipher,
        const uint8_t *key, size_t key_len,
        const uint8_t *iv, size_t iv_len,
        const uint8_t *plaintext, size_t plaintext_len,
        void *user_data);
int whisper_decrypt2(signal_buffer **output,
        int cipher,
        const uint8_t *key, size_t key_len,
        const uint8_t *iv, size_t iv_len,
        const uint8_t *ciphertext, size_t ciphertext_len,
        void *user_data);

/* Test data store context */

/* Test session store */
int session_store_load_session2(signal_buffer **record, const signal_protocol_address *address, void *user_data);
int session_store_get_sub_device_sessions2(signal_int_list **sessions, const char *name, size_t name_len, void *user_data);
int session_store_store_session2(const signal_protocol_address *address, uint8_t *record, size_t record_len, void *user_data);
int session_store_contains_session2(const signal_protocol_address *address, void *user_data);
int session_store_delete_session2(const signal_protocol_address *address, void *user_data);
int session_store_delete_all_sessions2(const char *name, size_t name_len, void *user_data);
void session_store_destroy2(void *user_data);
void setup_session_store2(signal_protocol_store_context *context);

/* Test pre-key store */
int pre_key_store_load_pre_key2(signal_buffer **record, uint32_t pre_key_id, void *user_data);
int pre_key_store_store_pre_key2(uint32_t pre_key_id, uint8_t *record, size_t record_len, void *user_data);
int pre_key_store_contains_pre_key2(uint32_t pre_key_id, void *user_data);
int pre_key_store_remove_pre_key2(uint32_t pre_key_id, void *user_data);
void pre_key_store_destroy2(void *user_data);
void setup_pre_key_store2(signal_protocol_store_context *context);

/* Test signed pre-key store */
int signed_pre_key_store_load_signed_pre_key2(signal_buffer **record, uint32_t signed_pre_key_id, void *user_data);
int signed_pre_key_store_store_signed_pre_key2(uint32_t signed_pre_key_id, uint8_t *record, size_t record_len, void *user_data);
int signed_pre_key_store_contains_signed_pre_key2(uint32_t signed_pre_key_id, void *user_data);
int signed_pre_key_store_remove_signed_pre_key2(uint32_t signed_pre_key_id, void *user_data);
void signed_pre_key_store_destroy2(void *user_data);
void setup_signed_pre_key_store2(signal_protocol_store_context *context);

/* Test identity key store */
int identity_key_store_get_identity_key_pair2(signal_buffer **public_data, signal_buffer **private_data, void *user_data);
int identity_key_store_get_local_registration_id2(void *user_data, uint32_t *registration_id);
int identity_key_store_save_identity2(const char *name, size_t name_len, uint8_t *key_data, size_t key_len, void *user_data);
int identity_key_store_is_trusted_identity2(const char *name, size_t name_len, uint8_t *key_data, size_t key_len, void *user_data);
void identity_key_store_destroy2(void *user_data);
void setup_identity_key_store2(signal_protocol_store_context *context, signal_context *global_context);

/* Test sender key store */
int sender_key_store_store_sender_key2(const signal_protocol_sender_key_name *sender_key_name, uint8_t *record, size_t record_len, void *user_data);
int sender_key_store_load_sender_key2(signal_buffer **record, const signal_protocol_sender_key_name *sender_key_name, void *user_data);
void sender_key_store_destroy2(void *user_data);
void setup_sender_key_store2(signal_protocol_store_context *context, signal_context *global_context);
void encryptMsg2(const char* currentUser,const char* receiverName, char* orignalMsg);
char* append(char *s1, char *s2);

char* base64_encode(char* plain);
 char* base64_decode(char* cipher);
 void initialize_sessions_v3(session_state *alice_state, session_state *bob_state, signal_context *global_context);

signal_context *signal_setup2(void);
void signal_destroy(signal_context *global_context);
 void setup_store_context2(signal_protocol_store_context **context, signal_context *global_context);

#endif /* COMMON_H */
