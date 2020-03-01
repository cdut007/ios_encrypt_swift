//
//  encrypt_common.c
//  libsignal-protocol-swift iOS
//
//  Created by mac on 2020/3/1.
//  Copyright © 2020 User. All rights reserved.
//

#include "encrypt_common.h"

#include <stdlib.h>
#include "session_record.h"
#include "session_state.h"
#include "session_cipher.h"
#include "ratchet.h"
#include <stdio.h>
#include <memory.h>
#include "protocol.h"
#include <pthread.h>
// #include <check.h>
#include "signal_protocol.h"
#include "curve.h"
#include "uthash.h"
#include "utarray.h"
#include <CommonCrypto/CommonDigest.h>
#include <CommonCrypto/CommonHMAC.h>
#include <CommonCrypto/CommonCryptor.h>
   
  pthread_mutex_t global_mutex;
  pthread_mutexattr_t global_mutex_attr;
  
  int set_locking(signal_context *global_context);
  void test_log2(int level, const char *message, size_t len, void *user_data);
 
  int setup_crypto_provider2(signal_context *context);

  signal_context *signal_setup2(void) {
        fprintf(stderr, "signal_setup2\n");
      signal_context *global_context;
      int result = signal_context_create(&global_context, 0);
      if (result != 0) {
          return 0;
      }

      result = set_locking(global_context);
      if (result != 0) {
          signal_context_destroy(global_context);
          return 0;
      }

      result = setup_crypto_provider2(global_context);
      if (result != 0) {
          fprintf(stderr, "signal_context_destroy???\n");
          signal_context_destroy(global_context);
          pthread_mutex_destroy(&global_mutex);
          pthread_mutexattr_destroy(&global_mutex_attr);
          return 0;
      }

      signal_context_set_log_function(global_context, test_log2);
      
      return (void*) global_context;
  }

  void signal_destroy(signal_context *global_context) {

      signal_context_destroy(global_context);

      pthread_mutex_destroy(&global_mutex);
      pthread_mutexattr_destroy(&global_mutex_attr);
  }

  // MARK: Locking functions

  void test_lock(void *user_data) {
      pthread_mutex_lock(&global_mutex);
  }

  void test_unlock(void *user_data) {
      pthread_mutex_unlock(&global_mutex);
  }

  int set_locking(signal_context *global_context) {
      pthread_mutexattr_init(&global_mutex_attr);
      pthread_mutexattr_settype(&global_mutex_attr, PTHREAD_MUTEX_RECURSIVE);
      pthread_mutex_init(&global_mutex, &global_mutex_attr);

      return signal_context_set_locking_functions(global_context, test_lock, test_unlock);
  }

  void test_log2(int level, const char *message, size_t len, void *user_data) {
      switch(level) {
          case SG_LOG_ERROR:
              fprintf(stderr, "[ERROR] %s\n", message);
              break;
          case SG_LOG_WARNING:
              fprintf(stderr, "[WARNING] %s\n", message);
              break;
          case SG_LOG_NOTICE:
              fprintf(stderr, "[NOTICE] %s\n", message);
              break;
          case SG_LOG_INFO:
              fprintf(stderr, "[INFO] %s\n", message);
              break;
          case SG_LOG_DEBUG:
              fprintf(stderr, "[DEBUG] %s\n", message);
              break;
          default:
              fprintf(stderr, "[%d] %s\n", level, message);
              break;
      }
  }

    
    char* encryptMsg2(const char* currentUser,const char* receiverName,const char* orignalMsg){
           signal_context* global_context = signal_setup2();
           fprintf(stderr, "encrypt msg\n");

            int result = 0;

            /* Create Alice's session record */
            session_record *alice_session_record = 0;
            fprintf(stderr, "session begin~~\n");
            result = session_record_create(&alice_session_record, 0, global_context);
            ////ck_assert_int_eq(result, 0);
            fprintf(stderr,"session_record_create result:%d\n",result);
            /* Create Bob's session record */
            session_record *bob_session_record = 0;
            result = session_record_create(&bob_session_record, 0, global_context);
            ////ck_assert_int_eq(result, 0);

             initialize_sessions_v3(
                    session_record_get_state(alice_session_record),
                    session_record_get_state(bob_session_record),global_context);

             size_t currentUserLen = strlen(currentUser);
             size_t receiverLen = strlen(receiverName);
             signal_protocol_address alice_address = {
                     currentUser, currentUserLen, 1
             };

             signal_protocol_address bob_address = {
                     receiverName, receiverLen, 1
             };

             fprintf(stderr," begin run_interaction\n");
             /* Create the test data stores */
             signal_protocol_store_context *alice_store = 0;
             setup_store_context2(&alice_store, global_context);
              
             /* Store the two sessions in their data stores */
             result = signal_protocol_session_store_session(alice_store, &alice_address, alice_session_record);
             fprintf(stderr," signal_protocol_session_store_session,result:%d\n",result);
             /* Create two session cipher instances */
             session_cipher *alice_cipher = 0;
             result = session_cipher_create(&alice_cipher, alice_store, &alice_address, global_context);

             fprintf(stderr," session_cipher_create,result:%d\n",result);
             ////ck_assert_int_eq(result, 0);

             /* Encrypt a test message from Alice */
             const char* alice_plaintext = orignalMsg;
             size_t msgLen = strlen(alice_plaintext);
             size_t alice_plaintext_len = msgLen;
             ciphertext_message *alice_message = 0;
             result = session_cipher_encrypt(alice_cipher, (uint8_t *)alice_plaintext, alice_plaintext_len, &alice_message);
             ////ck_assert_int_eq(result, 0);
             fprintf(stderr," session_cipher_encrypt,result:%d\n",result);
             /* Serialize and deserialize the test message to create a fresh instance */
             signal_buffer *alice_message_serialized = ciphertext_message_get_serialized(alice_message);
             //ck_assert_ptr_ne(alice_message_serialized, 0);

             size_t len = signal_buffer_len(alice_message_serialized);

             char * encrypt_chars = (char*)signal_buffer_data(alice_message_serialized);
             //content
             char *  encoded = base64_encode(encrypt_chars,len);

             fprintf(stderr,"ciphertext_message_get_serialized content encoded:%s,len %d\n",encoded,len);

             //serialized the session record.
             signal_buffer *buffer = 0;
             result = session_record_serialize(&buffer, bob_session_record);

             char *  data = (char*)signal_buffer_data(buffer);
             size_t record_len = signal_buffer_len(buffer);
             //key for base64
        char *  session_encoded = base64_encode(data,record_len);
             // session record
            fprintf(stderr,"ciphertext_message_get_serialized session_encoded encoded:%s,len %d\n",session_encoded,record_len);
             //change the position.
    //         char * random_chars =
    //                      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    //         int random_len = sizeof(random_chars);
    //         int pos = rand()%random_len;
            char* content;
            content = append(encoded, ".");
            content = append(content, "q");
            content = append(content, session_encoded);
         fprintf(stderr,"ciphertext_message_get_message Str:%s\n",content);
            /* Cleanup */
            SIGNAL_UNREF(alice_session_record);
            SIGNAL_UNREF(bob_session_record);
            signal_destroy(global_context);
        
        return content;
    }

    char* append(char *s1, char *s2)
    {
        char *result = malloc(strlen(s1)+strlen(s2)+1);//+1 for the zero-terminator
        //in real code you would check for errors in malloc here
     
        strcpy(result, s1);
        strcat(result, s2);
     
        return result;
    }
    

char* decryptMessage2(const char* encryptMsg ,const char* senderName, const char* decode_content,const char* decode_key){
      signal_context* global_context = signal_setup2();
      fprintf(stderr,"decrypt msg");

        int result = 0;

        /* Create Alice's session record */
         session_record *alice_session_record = 0;
        //  LOG(LS_INFO) << "session begin~~";
         result = session_record_create(&alice_session_record, 0, global_context);
        /* Create Bob's session record */
        session_record *bob_session_record = 0;
        result = session_record_create(&bob_session_record, 0, global_context);
        ////ck_assert_int_eq(result, 0);

        initialize_sessions_v3(
                session_record_get_state(alice_session_record),
                session_record_get_state(bob_session_record),global_context);


                char* decoded = encryptMsg;
                fprintf(stderr,"decrypt alice_plain_content,decoded:%s",decoded);
               
                
//                int startPos = decoded.find(std::string("."));
//                    if(startPos != std::string::npos){
//                        int sessionStartPos = startPos+1;
//                        int len = decoded.size();
//                        int sessionLen = len - sessionStartPos;
//                        int keyLen = startPos;
//                          decode_key = decoded.substr(sessionStartPos,sessionLen);
//                          //remove flag
//                          decode_key = decode_key.substr(1,sessionLen-1);
//
//                          decode_content  = decoded.substr(0,keyLen);
//
//                    }
              fprintf(stderr,"find session decode_content:%s decode_key:%s\n",decode_content, decode_key);
                /* Deserialize the record */
                char*  decode_content_origal,decode_key_origal;
                size_t orgLen=0,keyLen=0;
                size_t decode_content_len = strlen(decode_content),decode_key_len=strlen(decode_key);
                decode_content_origal = base64_decode(decode_content,decode_content_len,&orgLen);
                decode_key_origal = base64_decode(decode_key,decode_key_len,&keyLen);

                session_record *record_deserialized = 0;
                const char*  expr_session_record= decode_content;
                uint8_t * data = (uint8_t *)expr_session_record;


                result = session_record_deserialize(&record_deserialized, data, keyLen, global_context);
               fprintf(stderr,"find session org_key_len:%d , decode_key_len :%d ,result:%d\n" ,decode_key_len,keyLen,result);
                bob_session_record = record_deserialized;


        signal_protocol_address bob_address = {
                                senderName, strlen(senderName), 1
                        };
        /* Create the  data store */
        signal_protocol_store_context *bob_store = 0;
        setup_store_context2(&bob_store, global_context);
        fprintf(stderr,"begin signal_protocol_session_store_session\n");
        /* Store the  session in their data store */
        result = signal_protocol_session_store_session(bob_store, &bob_address, bob_session_record);
        /* Create  session cipher instance */
        session_cipher *bob_cipher = 0;
        result = session_cipher_create(&bob_cipher, bob_store, &bob_address, global_context);


        int decryptlen = orgLen;
        const char*  expr= decode_content_origal;
        uint8_t * message = (uint8_t *)expr;
        size_t alice_plain_content_len = decryptlen;
        fprintf(stderr," decrypt alice_plain_content_len,result:%d",alice_plain_content_len);
        signal_message *alice_message_deserialized = 0;
        result = signal_message_deserialize(&alice_message_deserialized,
                message,
                alice_plain_content_len,
                global_context);
        fprintf(stderr,"signal_message_deserialize,result:%d",result);
        /* Have Bob decrypt the test message */
        signal_buffer *bob_plaintext = 0;
        result = session_cipher_decrypt_signal_message(bob_cipher, alice_message_deserialized, 0, &bob_plaintext);
        ////ck_assert_int_eq(result, 0);
       fprintf(stderr,"session_cipher_decrypt_signal_message,result:%d",result);

        uint8_t *bob_plaintext_data = signal_buffer_data(bob_plaintext);
        size_t bob_plaintext_len = signal_buffer_len(bob_plaintext);

        /* in case you'd expect char buffer, just a byte to byte copy */
    char* decryptedMsg = (char*)bob_plaintext_data;
        fprintf(stderr,"session_cipher_decrypt_signal_message,content,%s",decryptedMsg);
        //ck_assert_int_eq(memcmp(alice_plaintext, bob_plaintext_data, bob_plaintext_len), 0);
        fprintf(stderr,"Interaction complete: Alice -> Bob\n");

        SIGNAL_UNREF(alice_message_deserialized);
        signal_buffer_free(bob_plaintext);
        session_cipher_free(bob_cipher);
        signal_protocol_store_context_destroy(bob_store);
        /* Cleanup */
        //SIGNAL_UNREF(alice_session_record);
        SIGNAL_UNREF(bob_session_record);
        signal_destroy(global_context);
                
                return decryptedMsg;
}



    void initialize_sessions_v3(session_state *alice_state, session_state *bob_state, signal_context *global_context)
    {
        int result = 0;

        /* Generate Alice's identity key */
        ec_key_pair *alice_identity_key_pair = 0;
        result = curve_generate_key_pair(global_context, &alice_identity_key_pair);
        ////ck_assert_int_eq(result, 0);
          fprintf(stderr,"curve_generate_key_pair identity result::%d\n",result);

        ratchet_identity_key_pair *alice_identity_key = 0;
        result = ratchet_identity_key_pair_create(&alice_identity_key,
                ec_key_pair_get_public(alice_identity_key_pair),
                ec_key_pair_get_private(alice_identity_key_pair));
        ////ck_assert_int_eq(result, 0);
        fprintf(stderr,"ratchet_identity_key_pair_create result::%d\n",result);
        SIGNAL_UNREF(alice_identity_key_pair);

        /* Generate Alice's base key */
        ec_key_pair *alice_base_key = 0;
        result = curve_generate_key_pair(global_context, &alice_base_key);
        ////ck_assert_int_eq(result, 0);
        fprintf(stderr,"curve_generate_key_pair base result:%d\n",result);
        /* Generate Alice's ephemeral key */
        ec_key_pair *alice_ephemeral_key = 0;
        result = curve_generate_key_pair(global_context, &alice_ephemeral_key);
        ////ck_assert_int_eq(result, 0);
        fprintf(stderr,"curve_generate_key_pair ephemeral result:%d\n",result);
        /* Generate Alice's pre-key */
        ec_key_pair *alice_pre_key = alice_base_key;
        SIGNAL_REF(alice_base_key);

        /* Generate Bob's identity key */
        ec_key_pair *bob_identity_key_pair = 0;
        result = curve_generate_key_pair(global_context, &bob_identity_key_pair);
        ////ck_assert_int_eq(result, 0);

        ratchet_identity_key_pair *bob_identity_key = 0;
        result = ratchet_identity_key_pair_create(&bob_identity_key,
                ec_key_pair_get_public(bob_identity_key_pair),
                ec_key_pair_get_private(bob_identity_key_pair));
        ////ck_assert_int_eq(result, 0);
        SIGNAL_UNREF(bob_identity_key_pair);

        /* Generate Bob's base key */
        ec_key_pair *bob_base_key = 0;
        result = curve_generate_key_pair(global_context, &bob_base_key);
        ////ck_assert_int_eq(result, 0);

        /* Generate Bob's ephemeral key */
        ec_key_pair *bob_ephemeral_key = bob_base_key;
        SIGNAL_REF(bob_base_key);

        /* Generate Bob's pre-key */
        ec_key_pair *bob_pre_key;
        result = curve_generate_key_pair(global_context, &bob_pre_key);
        ////ck_assert_int_eq(result, 0);

        /* Create Alice's parameters */
        alice_signal_protocol_parameters *alice_parameters = 0;
        result = alice_signal_protocol_parameters_create(&alice_parameters,
                /* our_identity_key       */ alice_identity_key,
                /* our_base_key           */ alice_base_key,
                /* their_identity_key     */ ratchet_identity_key_pair_get_public(bob_identity_key),
                /* their_signed_pre_key   */ ec_key_pair_get_public(bob_base_key),
                /* their_one_time_pre_key */ 0,
                /* their_ratchet_key      */ ec_key_pair_get_public(bob_ephemeral_key));
        ////ck_assert_int_eq(result, 0);
        fprintf(stderr,"alice_signal_protocol_parameters_create  result:%d\n",result);
        /* Create Bob's parameters */
        bob_signal_protocol_parameters *bob_parameters = 0;
        result = bob_signal_protocol_parameters_create(&bob_parameters,
                /* our_identity_key     */ bob_identity_key,
                /* our_signed_pre_key   */ bob_base_key,
                /* our_one_time_pre_key */ 0,
                /* our_ratchet_key      */ bob_ephemeral_key,
                /* their_identity_key   */ ratchet_identity_key_pair_get_public(alice_identity_key),
                /* their_base_key       */ ec_key_pair_get_public(alice_base_key));
        ////ck_assert_int_eq(result, 0);

        /* Initialize the ratcheting sessions */
        result = ratcheting_session_alice_initialize(alice_state, alice_parameters, global_context);
        ////ck_assert_int_eq(result, 0);
        fprintf(stderr,"ratcheting_session_alice_initialize  result:%d\n",result);

        result = ratcheting_session_bob_initialize(bob_state, bob_parameters, global_context);
        ////ck_assert_int_eq(result, 0);
        fprintf(stderr,"ratcheting_session_bob_initialize  result:%d\n",result);

        /* Unref cleanup */
        SIGNAL_UNREF(alice_identity_key);
        SIGNAL_UNREF(alice_base_key);
        SIGNAL_UNREF(alice_ephemeral_key);
        SIGNAL_UNREF(alice_pre_key);
        SIGNAL_UNREF(bob_identity_key);
        SIGNAL_UNREF(bob_base_key);
        SIGNAL_UNREF(bob_ephemeral_key);
        SIGNAL_UNREF(bob_pre_key);
        SIGNAL_UNREF(alice_parameters);
        SIGNAL_UNREF(bob_parameters);
    }


static const unsigned char base64_table[65] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";





    char base46_map[] = {'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
                         'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f',
                         'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
                         'w', 'x', 'y', 'z', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '+', '/'};


char* base64_encode(char *src, size_t len) {
    unsigned char *out, *pos;
       const unsigned char *end, *in;
    size_t *out_len = 0;
       size_t olen;
       int line_len;

       olen = len * 4 / 3 + 4; /* 3-byte blocks to 4-byte */
       olen += olen / 72; /* line feeds */
       olen++; /* nul termination */
       if (olen < len)
           return NULL; /* integer overflow */
       out = malloc(olen);
       if (out == NULL)
           return NULL;

       end = src + len;
       in = src;
       pos = out;
       line_len = 0;
       while (end - in >= 3) {
           *pos++ = base64_table[in[0] >> 2];
           *pos++ = base64_table[((in[0] & 0x03) << 4) | (in[1] >> 4)];
           *pos++ = base64_table[((in[1] & 0x0f) << 2) | (in[2] >> 6)];
           *pos++ = base64_table[in[2] & 0x3f];
           in += 3;
           line_len += 4;
           if (line_len >= 72) {
               *pos++ = '\n';
               line_len = 0;
           }
       }

       if (end - in) {
           *pos++ = base64_table[in[0] >> 2];
           if (end - in == 1) {
               *pos++ = base64_table[(in[0] & 0x03) << 4];
               *pos++ = '=';
           } else {
               *pos++ = base64_table[((in[0] & 0x03) << 4) |
                             (in[1] >> 4)];
               *pos++ = base64_table[(in[1] & 0x0f) << 2];
           }
           *pos++ = '=';
           line_len += 4;
       }

       if (line_len)
           *pos++ = '\n';

       *pos = '\0';
       if (out_len)
           *out_len = pos - out;
       return out;
        
    }


    unsigned char * base64_decode(const unsigned char *src, size_t len,
                                  size_t *out_len)
                {
                    unsigned char dtable[256], *out, *pos, block[4], tmp;
                    size_t i, count, olen;
                    int pad = 0;

                    memset(dtable, 0x80, 256);
                    for (i = 0; i < sizeof(base64_table) - 1; i++)
                        dtable[base64_table[i]] = (unsigned char) i;
                    dtable['='] = 0;

                    count = 0;
                    for (i = 0; i < len; i++) {
                        if (dtable[src[i]] != 0x80)
                            count++;
                    }

                    if (count == 0 || count % 4)
                        return NULL;

                    olen = count / 4 * 3;
                    pos = out = malloc(olen);
                    if (out == NULL)
                        return NULL;

                    count = 0;
                    for (i = 0; i < len; i++) {
                        tmp = dtable[src[i]];
                        if (tmp == 0x80)
                            continue;

                        if (src[i] == '=')
                            pad++;
                        block[count] = tmp;
                        count++;
                        if (count == 4) {
                            *pos++ = (block[0] << 2) | (block[1] >> 4);
                            *pos++ = (block[1] << 4) | (block[2] >> 2);
                            *pos++ = (block[2] << 6) | block[3];
                            count = 0;
                            if (pad) {
                                if (pad == 1)
                                    pos--;
                                else if (pad == 2)
                                    pos -= 2;
                                else {
                                    /* Invalid padding */
                                    free(out);
                                    return NULL;
                                }
                                break;
                            }
                        }
                    }

                    *out_len = pos - out;
                    return out;
                }
    
                


    
    
    
    
    /*
     * This is an implementation of Jenkin's "One-at-a-Time" hash.
     *
     * http://www.burtleburtle.net/bob/hash/doobs.html
     *
     * It is used to simplify using our new string recipient IDs
     * as part of our keys without having to significantly modify the
     * testing-only implementations of our data stores.
     */
    int64_t jenkins_hash2(const char *key, size_t len)
    {
        uint64_t hash, i;
        for(hash = i = 0; i < len; ++i) {
            hash += key[i];
            hash += (hash << 10);
            hash ^= (hash >> 6);
        }
        hash += (hash << 3);
        hash ^= (hash >> 11);
        hash += (hash << 15);
        return hash;
    }

    void print_public_key2(const char *prefix, ec_public_key *key)
    {
        signal_buffer *buffer;
        ec_public_key_serialize(&buffer, key);

        fprintf(stderr, "%s ", prefix);
        uint8_t *data = signal_buffer_data(buffer);
        int len = signal_buffer_len(buffer);
        int i;
        for(i = 0; i < len; i++) {
            if(i > 0 && (i % 40) == 0) {
                fprintf(stderr, "\n");
            }
            fprintf(stderr, "%02X", data[i]);
        }
        fprintf(stderr, "\n");
        signal_buffer_free(buffer);
    }

    void print_buffer2(const char *prefix, signal_buffer *buffer)
    {
        fprintf(stderr, "%s ", prefix);
        uint8_t *data = signal_buffer_data(buffer);
        int len = signal_buffer_len(buffer);
        int i;
        for(i = 0; i < len; i++) {
            if(i > 0 && (i % 40) == 0) {
                fprintf(stderr, "\n");
            }
            fprintf(stderr, "%02X", data[i]);
        }
        fprintf(stderr, "\n");
    }

    void shuffle_buffers2(signal_buffer **array, size_t n)
    {
        if (n > 1) {
            size_t i;
            for (i = 0; i < n - 1; i++) {
                size_t j = i + rand() / (RAND_MAX / (n - i) + 1);
                signal_buffer *t = array[j];
                array[j] = array[i];
                array[i] = t;
            }
        }
    }

    ec_public_key *create_ec_public_key2(signal_context *context)
    {
        int result = 0;
        ec_key_pair *key_pair;
        result = curve_generate_key_pair(context, &key_pair);
        //ck_assert_int_eq(result, 0);

        ec_public_key *public_key = ec_key_pair_get_public(key_pair);
        SIGNAL_REF(public_key);
        SIGNAL_UNREF(key_pair);
        return public_key;
    }

    ec_private_key *create_ec_private_key2(signal_context *context)
    {
        int result = 0;
        ec_key_pair *key_pair;
        result = curve_generate_key_pair(context, &key_pair);
        //ck_assert_int_eq(result, 0);

        ec_private_key *private_key = ec_key_pair_get_private(key_pair);
        SIGNAL_REF(private_key);
        SIGNAL_UNREF(key_pair);
        return private_key;
    }

    void common_log2(int level, const char *message, size_t len, void *user_data)
    {
        switch(level) {
        case SG_LOG_ERROR:
            fprintf(stderr, "[ERROR] %s\n", message);
            break;
        case SG_LOG_WARNING:
            fprintf(stderr, "[WARNING] %s\n", message);
            break;
        case SG_LOG_NOTICE:
            fprintf(stderr, "[NOTICE] %s\n", message);
            break;
        case SG_LOG_INFO:
            fprintf(stderr, "[INFO] %s\n", message);
            break;
        case SG_LOG_DEBUG:
            fprintf(stderr, "[DEBUG] %s\n", message);
            break;
        default:
            fprintf(stderr, "[%d] %s\n", level, message);
            break;
        }
    }

    int random_generator2(uint8_t *data, size_t len, void *user_data)
    {
        /*
             * Apple's documentation recommends this method for generating secure
             * random numbers.
             */
            int result = 0;

            FILE *fp = fopen("/dev/random", "r");
            if(!fp) {
                result = SG_ERR_UNKNOWN;
                goto complete;
            }

            size_t n = fread(data, 1, len, fp);
            if(n != len) {
                result = SG_ERR_UNKNOWN;
                goto complete;
            }

        complete:
            if(fp) {
                fclose(fp);
            }
            return result;
    }

    int hmac_sha256_init2(void **hmac_context, const uint8_t *key, size_t key_len, void *user_data)
    {
        CCHmacContext *ctx = malloc(sizeof(CCHmacContext));
        if(!ctx) {
            return SG_ERR_NOMEM;
        }

        CCHmacInit(ctx, kCCHmacAlgSHA256, key, key_len);
        *hmac_context = ctx;

        return 0;
    }

    int hmac_sha256_update2(void *hmac_context, const uint8_t *data, size_t data_len, void *user_data)
    {
        CCHmacContext *ctx = hmac_context;
        CCHmacUpdate(ctx, data, data_len);
        return 0;
    }

    int hmac_sha256_final2(void *hmac_context, signal_buffer **output, void *user_data)
    {
         CCHmacContext *ctx = hmac_context;

           signal_buffer *output_buffer = signal_buffer_alloc(CC_SHA256_DIGEST_LENGTH);
           if(!output_buffer) {
               return SG_ERR_NOMEM;
           }

           CCHmacFinal(ctx, signal_buffer_data(output_buffer));

           *output = output_buffer;

           return 0;
    }

    void hmac_sha256_cleanup2(void *hmac_context, void *user_data)
    {
        if(hmac_context) {
            CCHmacContext *ctx = hmac_context;
            free(ctx);
        }
    }

  
    
    int sha512_digest_init2(signal_buffer **output, const uint8_t *data, size_t data_len, void *user_data)
    {
        void **digest_context = 0;
        int result = 0;

        CC_SHA512_CTX *ctx = malloc(sizeof(CC_SHA512_CTX));
        if(!ctx) {
            result = SG_ERR_NOMEM;
            goto complete;
        }

        result = CC_SHA512_Init(ctx);
        if(result != 1) {
            result = SG_ERR_UNKNOWN;
            goto complete;
        }

    complete:
        if(result < 0) {
            if(ctx) {
                free(ctx);
            }
        }
        else {
            *digest_context = ctx;
        }
        
        sha512_digest_update2(*digest_context,data,data_len,user_data);
        sha512_digest_final2(*digest_context,output,user_data);
        sha512_digest_cleanup2(*digest_context, user_data);
        
        
        return result;
    }

    int sha512_digest_update2(void *digest_context, const uint8_t *data, size_t data_len, void *user_data)
    {
        CC_SHA512_CTX *ctx = digest_context;

        int result = CC_SHA512_Update(ctx, data, (CC_LONG) data_len);

        return (result == 1) ? SG_SUCCESS : SG_ERR_UNKNOWN;
    }

    int sha512_digest_final2(void *digest_context, signal_buffer **output, void *user_data)
    {
        int result = 0;
        unsigned char md[CC_SHA512_DIGEST_LENGTH];
        CC_SHA512_CTX *ctx = digest_context;

        result = CC_SHA512_Final(md, ctx);
        if(result == 1) {
            result = SG_SUCCESS;
        }
        else {
            result = SG_ERR_UNKNOWN;
            goto complete;
        }

        result = CC_SHA512_Init(ctx);
        if(result == 1) {
            result = SG_SUCCESS;
        }
        else {
            result = SG_ERR_UNKNOWN;
            goto complete;
        }

        signal_buffer *output_buffer = signal_buffer_create(md, CC_SHA512_DIGEST_LENGTH);
        if(!output_buffer) {
            result = SG_ERR_NOMEM;
            goto complete;
        }

        *output = output_buffer;

    complete:
        return result;
    }

    void sha512_digest_cleanup2(void *digest_context, void *user_data)
    {
        if(digest_context) {
            CC_SHA512_CTX *ctx = digest_context;
            free(ctx);
        }
    }

    
    int cc_status_to_result2(CCCryptorStatus status)
    {
        switch(status) {
            case kCCSuccess:
                return SG_SUCCESS;
            case kCCParamError:
            case kCCBufferTooSmall:
                return SG_ERR_INVAL;
            case kCCMemoryFailure:
                return SG_ERR_NOMEM;
            case kCCAlignmentError:
            case kCCDecodeError:
            case kCCUnimplemented:
            case kCCOverflow:
            case kCCRNGFailure:
            case kCCUnspecifiedError:
            case kCCCallSequenceError:
            default:
                return SG_ERR_UNKNOWN;
        }
    }

  int whisper_encrypt2(signal_buffer **output,
                   int cipher,
                   const uint8_t *key, size_t key_len,
                   const uint8_t *iv, size_t iv_len,
                   const uint8_t *plaintext, size_t plaintext_len,
                   void *user_data)
  {
      int result = 0;
      uint8_t *out_buf = 0;
      CCCryptorStatus status = kCCSuccess;
      CCCryptorRef ref = 0;

      if(cipher == SG_CIPHER_AES_CBC_PKCS5) {
          status = CCCryptorCreate(kCCEncrypt, kCCAlgorithmAES, kCCOptionPKCS7Padding, key, key_len, iv, &ref);
      }
      else if(cipher == SG_CIPHER_AES_CTR_NOPADDING) {
          status = CCCryptorCreateWithMode(kCCEncrypt, kCCModeCTR, kCCAlgorithmAES, ccNoPadding,
                                           iv, key, key_len, 0, 0, 0, kCCModeOptionCTR_BE, &ref);
      }
      else {
          status = kCCParamError;
      }
      if(status != kCCSuccess) {
          result = cc_status_to_result2(status);
          goto complete;
      }

      size_t available_len = CCCryptorGetOutputLength(ref, plaintext_len, 1);
      out_buf = malloc(available_len);
      if(!out_buf) {
          fprintf(stderr, "cannot allocate output buffer\n");
          result = SG_ERR_NOMEM;
          goto complete;
      }

      size_t update_moved_len = 0;
      status = CCCryptorUpdate(ref, plaintext, plaintext_len, out_buf, available_len, &update_moved_len);
      if(status != kCCSuccess) {
          result = cc_status_to_result2(status);
          goto complete;
      }

      size_t final_moved_len = 0;
      status = CCCryptorFinal(ref, out_buf + update_moved_len, available_len - update_moved_len, &final_moved_len);
      if(status != kCCSuccess) {
          result = cc_status_to_result2(status);
          goto complete;
      }

      signal_buffer *output_buffer = signal_buffer_create(out_buf, update_moved_len + final_moved_len);
      if(!output_buffer) {
          result = SG_ERR_NOMEM;
          goto complete;
      }

      *output = output_buffer;

  complete:
      if(ref) {
          CCCryptorRelease(ref);
      }
      if(out_buf) {
          free(out_buf);
      }
      return result;
  }

  int whisper_decrypt2(signal_buffer **output,
                   int cipher,
                   const uint8_t *key, size_t key_len,
                   const uint8_t *iv, size_t iv_len,
                   const uint8_t *ciphertext, size_t ciphertext_len,
                   void *user_data)
  {
      int result = 0;
      uint8_t *out_buf = 0;
      CCCryptorStatus status = kCCSuccess;
      CCCryptorRef ref = 0;

      if(cipher == SG_CIPHER_AES_CBC_PKCS5) {
          status = CCCryptorCreate(kCCDecrypt, kCCAlgorithmAES, kCCOptionPKCS7Padding, key, key_len, iv, &ref);
      }
      else if(cipher == SG_CIPHER_AES_CTR_NOPADDING) {
          status = CCCryptorCreateWithMode(kCCDecrypt, kCCModeCTR, kCCAlgorithmAES, ccNoPadding,
                                           iv, key, key_len, 0, 0, 0, kCCModeOptionCTR_BE, &ref);
      }
      else {
          status = kCCParamError;
      }
      if(status != kCCSuccess) {
          result = cc_status_to_result2(status);
          goto complete;
      }

      out_buf = malloc(sizeof(uint8_t) * ciphertext_len);
      if(!out_buf) {
          fprintf(stderr, "cannot allocate output buffer\n");
          result = SG_ERR_UNKNOWN;
          goto complete;
      }

      size_t update_moved_len = 0;
      status = CCCryptorUpdate(ref, ciphertext, ciphertext_len, out_buf, ciphertext_len, &update_moved_len);
      if(status != kCCSuccess) {
          result = cc_status_to_result2(status);
          goto complete;
      }

      size_t final_moved_len = 0;
      status = CCCryptorFinal(ref, out_buf + update_moved_len, ciphertext_len - update_moved_len, &final_moved_len);
      if(status != kCCSuccess) {
          result = cc_status_to_result2(status);
          goto complete;
      }

      signal_buffer *output_buffer = signal_buffer_create(out_buf, update_moved_len + final_moved_len);
      if(!output_buffer) {
          result = SG_ERR_NOMEM;
          goto complete;
      }

      *output = output_buffer;

  complete:
      if(ref) {
          CCCryptorRelease(ref);
      }
      if(out_buf) {
          free(out_buf);
      }
      return result;
  }

    

    int setup_crypto_provider2(signal_context *context)
    {
        signal_crypto_provider provider = {
                .random_func = random_generator2,
                .hmac_sha256_init_func = hmac_sha256_init2,
                .hmac_sha256_update_func = hmac_sha256_update2,
                .hmac_sha256_final_func = hmac_sha256_final2,
                .hmac_sha256_cleanup_func = hmac_sha256_cleanup2,
                 .sha512_digest_func = sha512_digest_init2,
                .encrypt_func = whisper_encrypt2,
                .decrypt_func = whisper_decrypt2,
                .user_data = 0
        };

    return signal_context_set_crypto_provider(context, &provider);
    }
    
    typedef struct {
        int64_t recipient_id;
        int32_t device_id;
    } session_store_session_key;

    typedef struct {
        session_store_session_key key;
        signal_buffer *record;
        UT_hash_handle hh;
    } session_store_session;
    
    typedef struct {
          session_store_session *sessions;
      } session_store_data;
    
    void setup_session_store2(signal_protocol_store_context *context)
       {
           fprintf(stderr," setup_session_store begin \n");
           session_store_data *data = (session_store_data*)malloc(sizeof(session_store_data));
           memset(data, 0, sizeof(session_store_data));

           signal_protocol_session_store store = {
               .load_session_func = session_store_load_session2,
               .get_sub_device_sessions_func = session_store_get_sub_device_sessions2,
               .store_session_func = session_store_store_session2,
               .contains_session_func = session_store_contains_session2,
               .delete_session_func = session_store_delete_session2,
               .delete_all_sessions_func = session_store_delete_all_sessions2,
               .destroy_func = session_store_destroy2,
               .user_data = data
           };
          
           signal_protocol_store_context_set_session_store(context, &store);
           fprintf(stderr," setup_session_store end \n");
       }

    
    /*------------------------------------------------------------------------*/

    void setup_store_context2(signal_protocol_store_context **context, signal_context *global_context)
    {
        int result = 0;
        
        signal_protocol_store_context *store_context = 0;
        result = signal_protocol_store_context_create(&store_context, global_context);
        //ck_assert_int_eq(result, 0);

        setup_session_store2(store_context);
        setup_pre_key_store2(store_context);
        setup_signed_pre_key_store2(store_context);
        setup_identity_key_store2(store_context, global_context);
        setup_sender_key_store2(store_context, global_context);

        *context = store_context;
        fprintf(stderr," setup_store_context2 result:%d\n",result);
    }

    /*------------------------------------------------------------------------*/


  

    int session_store_load_session2(signal_buffer **record, const signal_protocol_address *address, void *user_data)
    {
        session_store_data *data = (session_store_data*)user_data;

        session_store_session *s;

        session_store_session l;
        memset(&l, 0, sizeof(session_store_session));
        l.key.recipient_id = jenkins_hash2(address->name, address->name_len);
        l.key.device_id = address->device_id;
        HASH_FIND(hh, data->sessions, &l.key, sizeof(session_store_session_key), s);

        if(!s) {
            return 0;
        }
        signal_buffer *result = signal_buffer_copy(s->record);
        if(!result) {
            return SG_ERR_NOMEM;
        }
        *record = result;
        return 1;
    }

    int session_store_get_sub_device_sessions2(signal_int_list **sessions, const char *name, size_t name_len, void *user_data)
    {
        session_store_data *data = (session_store_data*)user_data;

        signal_int_list *result = signal_int_list_alloc();
        if(!result) {
            return SG_ERR_NOMEM;
        }

        int64_t recipient_hash = jenkins_hash2(name, name_len);
        session_store_session *cur_node;
        session_store_session *tmp_node;
        HASH_ITER(hh, data->sessions, cur_node, tmp_node) {
            if(cur_node->key.recipient_id == recipient_hash) {
                signal_int_list_push_back(result, cur_node->key.device_id);
            }
        }

        *sessions = result;
        return 0;
    }

    int session_store_store_session2(const signal_protocol_address *address, uint8_t *record, size_t record_len, void *user_data)
    {
        session_store_data *data = (session_store_data*)user_data;
        session_store_session *s;

        session_store_session l;
        memset(&l, 0, sizeof(session_store_session));
        l.key.recipient_id = jenkins_hash2(address->name, address->name_len);
        l.key.device_id = address->device_id;

        signal_buffer *record_buf = signal_buffer_create(record, record_len);
        if(!record_buf) {
            return SG_ERR_NOMEM;
        }

        HASH_FIND(hh, data->sessions, &l.key, sizeof(session_store_session_key), s);

        if(s) {
            signal_buffer_free(s->record);
            s->record = record_buf;
        }
        else {
            s = (session_store_session*)malloc(sizeof(session_store_session));
            if(!s) {
                signal_buffer_free(record_buf);
                return SG_ERR_NOMEM;
            }
            memset(s, 0, sizeof(session_store_session));
            s->key.recipient_id = jenkins_hash2(address->name, address->name_len);
            s->key.device_id = address->device_id;
            s->record = record_buf;
            HASH_ADD(hh, data->sessions, key, sizeof(session_store_session_key), s);
        }

        return 0;
    }

    int session_store_contains_session2(const signal_protocol_address *address, void *user_data)
    {
        session_store_data *data = (session_store_data*)user_data;
        session_store_session *s;

        session_store_session l;
        memset(&l, 0, sizeof(session_store_session));
        l.key.recipient_id = jenkins_hash2(address->name, address->name_len);
        l.key.device_id = address->device_id;

        HASH_FIND(hh, data->sessions, &l.key, sizeof(session_store_session_key), s);

        return (s == 0) ? 0 : 1;
    }

    int session_store_delete_session2(const signal_protocol_address *address, void *user_data)
    {
        int result = 0;
        session_store_data *data = (session_store_data*)user_data;
        session_store_session *s;

        session_store_session l;
        memset(&l, 0, sizeof(session_store_session));
        l.key.recipient_id = jenkins_hash2(address->name, address->name_len);
        l.key.device_id = address->device_id;

        HASH_FIND(hh, data->sessions, &l.key, sizeof(session_store_session_key), s);

        if(s) {
            HASH_DEL(data->sessions, s);
            signal_buffer_free(s->record);
            free(s);
            result = 1;
        }
        return result;
    }

    int session_store_delete_all_sessions2(const char *name, size_t name_len, void *user_data)
    {
        int result = 0;
        session_store_data *data = (session_store_data*)user_data;

        int64_t recipient_hash = jenkins_hash2(name, name_len);
        session_store_session *cur_node;
        session_store_session *tmp_node;
        HASH_ITER(hh, data->sessions, cur_node, tmp_node) {
            if(cur_node->key.recipient_id == recipient_hash) {
                HASH_DEL(data->sessions, cur_node);
                signal_buffer_free(cur_node->record);
                free(cur_node);
                result++;
            }
        }

        return result;
    }

    void session_store_destroy2(void *user_data)
    {
        session_store_data *data = (session_store_data*)user_data;

        session_store_session *cur_node;
        session_store_session *tmp_node;
        HASH_ITER(hh, data->sessions, cur_node, tmp_node) {
            HASH_DEL(data->sessions, cur_node);
            signal_buffer_free(cur_node->record);
            free(cur_node);
        }

        free(data);
    }

   
    /*------------------------------------------------------------------------*/

    typedef struct {
        uint32_t key_id;
        signal_buffer *key_record;
        UT_hash_handle hh;
    } pre_key_store_key;

    typedef struct {
        pre_key_store_key *keys;
    } pre_key_store_data;

    int pre_key_store_load_pre_key2(signal_buffer **record, uint32_t pre_key_id, void *user_data)
    {
        pre_key_store_data *data = (pre_key_store_data*)user_data;

        pre_key_store_key *s;

        HASH_FIND(hh, data->keys, &pre_key_id, sizeof(uint32_t), s);
        if(s) {
            *record = signal_buffer_copy(s->key_record);
            return SG_SUCCESS;
        }
        else {
            return SG_ERR_INVALID_KEY_ID;
        }
    }

    int pre_key_store_store_pre_key2(uint32_t pre_key_id, uint8_t *record, size_t record_len, void *user_data)
    {
        pre_key_store_data *data = (pre_key_store_data*)user_data;

        pre_key_store_key *s;

        signal_buffer *key_buf = signal_buffer_create(record, record_len);
        if(!key_buf) {
            return SG_ERR_NOMEM;
        }

        HASH_FIND(hh, data->keys, &pre_key_id, sizeof(uint32_t), s);
        if(s) {
            signal_buffer_free(s->key_record);
            s->key_record = key_buf;
        }
        else {
            s = (pre_key_store_key*)malloc(sizeof(pre_key_store_key));
            if(!s) {
                signal_buffer_free(key_buf);
                return SG_ERR_NOMEM;
            }
            memset(s, 0, sizeof(pre_key_store_key));
            s->key_id = pre_key_id;
            s->key_record = key_buf;
            HASH_ADD(hh, data->keys, key_id, sizeof(uint32_t), s);
        }

        return 0;
    }

    int pre_key_store_contains_pre_key2(uint32_t pre_key_id, void *user_data)
    {
        pre_key_store_data *data = (pre_key_store_data*)user_data;

        pre_key_store_key *s;
        HASH_FIND(hh, data->keys, &pre_key_id, sizeof(uint32_t), s);

        return (s == 0) ? 0 : 1;
    }

    int pre_key_store_remove_pre_key2(uint32_t pre_key_id, void *user_data)
    {
        pre_key_store_data *data = (pre_key_store_data*)user_data;

        pre_key_store_key *s;
        HASH_FIND(hh, data->keys, &pre_key_id, sizeof(uint32_t), s);
        if(s) {
            HASH_DEL(data->keys, s);
            signal_buffer_free(s->key_record);
            free(s);
        }

        return 0;
    }

    void pre_key_store_destroy2(void *user_data)
    {
        pre_key_store_data *data = (pre_key_store_data*)user_data;

        pre_key_store_key *cur_node;
        pre_key_store_key *tmp_node;
        HASH_ITER(hh, data->keys, cur_node, tmp_node) {
            HASH_DEL(data->keys, cur_node);
            signal_buffer_free(cur_node->key_record);
            free(cur_node);
        }
        free(data);
    }

    void setup_pre_key_store2(signal_protocol_store_context *context)
    {
        pre_key_store_data *data = (pre_key_store_data*)malloc(sizeof(pre_key_store_data));
        memset(data, 0, sizeof(pre_key_store_data));

        signal_protocol_pre_key_store store = {
            .load_pre_key = pre_key_store_load_pre_key2,
            .store_pre_key = pre_key_store_store_pre_key2,
            .contains_pre_key = pre_key_store_contains_pre_key2,
            .remove_pre_key = pre_key_store_remove_pre_key2,
            .destroy_func = pre_key_store_destroy2,
            .user_data = data
        };

        signal_protocol_store_context_set_pre_key_store(context, &store);
    }

    /*------------------------------------------------------------------------*/

    typedef struct {
        uint32_t key_id;
        signal_buffer *key_record;
        UT_hash_handle hh;
    } signed_pre_key_store_key;

    typedef struct {
        signed_pre_key_store_key *keys;
    } signed_pre_key_store_data;


    int signed_pre_key_store_load_signed_pre_key2(signal_buffer **record, uint32_t signed_pre_key_id, void *user_data)
    {
        signed_pre_key_store_data *data = (signed_pre_key_store_data*)user_data;
        signed_pre_key_store_key *s;

        HASH_FIND(hh, data->keys, &signed_pre_key_id, sizeof(uint32_t), s);
        if(s) {
            *record = signal_buffer_copy(s->key_record);
            return SG_SUCCESS;
        }
        else {
            return SG_ERR_INVALID_KEY_ID;
        }
    }

    int signed_pre_key_store_store_signed_pre_key2(uint32_t signed_pre_key_id, uint8_t *record, size_t record_len, void *user_data)
    {
        signed_pre_key_store_data *data = (signed_pre_key_store_data*)user_data;
        signed_pre_key_store_key *s;

        signal_buffer *key_buf = signal_buffer_create(record, record_len);
        if(!key_buf) {
            return SG_ERR_NOMEM;
        }

        HASH_FIND(hh, data->keys, &signed_pre_key_id, sizeof(uint32_t), s);
        if(s) {
            signal_buffer_free(s->key_record);
            s->key_record = key_buf;
        }
        else {
            s = (signed_pre_key_store_key*)malloc(sizeof(signed_pre_key_store_key));
            if(!s) {
                signal_buffer_free(key_buf);
                return SG_ERR_NOMEM;
            }
            memset(s, 0, sizeof(signed_pre_key_store_key));
            s->key_id = signed_pre_key_id;
            s->key_record = key_buf;
            HASH_ADD(hh, data->keys, key_id, sizeof(uint32_t), s);
        }

        return 0;
    }

    int signed_pre_key_store_contains_signed_pre_key2(uint32_t signed_pre_key_id, void *user_data)
    {
        signed_pre_key_store_data *data = (signed_pre_key_store_data*)user_data;

        signed_pre_key_store_key *s;
        HASH_FIND(hh, data->keys, &signed_pre_key_id, sizeof(uint32_t), s);

        return (s == 0) ? 0 : 1;
    }

    int signed_pre_key_store_remove_signed_pre_key2(uint32_t signed_pre_key_id, void *user_data)
    {
        signed_pre_key_store_data *data = (signed_pre_key_store_data*)user_data;

        signed_pre_key_store_key *s;
        HASH_FIND(hh, data->keys, &signed_pre_key_id, sizeof(uint32_t), s);
        if(s) {
            HASH_DEL(data->keys, s);
            signal_buffer_free(s->key_record);
            free(s);
        }

        return 0;
    }

    void signed_pre_key_store_destroy2(void *user_data)
    {
        signed_pre_key_store_data *data = (signed_pre_key_store_data*)user_data;

        signed_pre_key_store_key *cur_node;
        signed_pre_key_store_key *tmp_node;
        HASH_ITER(hh, data->keys, cur_node, tmp_node) {
            HASH_DEL(data->keys, cur_node);
            signal_buffer_free(cur_node->key_record);
            free(cur_node);
        }
        free(data);
    }

    void setup_signed_pre_key_store2(signal_protocol_store_context *context)
    {
        signed_pre_key_store_data *data = (signed_pre_key_store_data*)malloc(sizeof(signed_pre_key_store_data));
        memset(data, 0, sizeof(signed_pre_key_store_data));

        signal_protocol_signed_pre_key_store store = {
                .load_signed_pre_key = signed_pre_key_store_load_signed_pre_key2,
                .store_signed_pre_key = signed_pre_key_store_store_signed_pre_key2,
                .contains_signed_pre_key = signed_pre_key_store_contains_signed_pre_key2,
                .remove_signed_pre_key = signed_pre_key_store_remove_signed_pre_key2,
                .destroy_func = signed_pre_key_store_destroy2,
                .user_data = data
        };

        signal_protocol_store_context_set_signed_pre_key_store(context, &store);
    }

    /*------------------------------------------------------------------------*/

    typedef struct {
        int64_t recipient_id;
        signal_buffer *identity_key;
        UT_hash_handle hh;
    } identity_store_key;

    typedef struct {
        identity_store_key *keys;
        signal_buffer *identity_key_public;
        signal_buffer *identity_key_private;
        uint32_t local_registration_id;
    } identity_store_data;

    int identity_key_store_get_identity_key_pair2(signal_buffer **public_data, signal_buffer **private_data, void *user_data)
    {
        identity_store_data *data = (identity_store_data*)user_data;
        *public_data = signal_buffer_copy(data->identity_key_public);
        *private_data = signal_buffer_copy(data->identity_key_private);
        return 0;
    }

    int identity_key_store_get_local_registration_id2(void *user_data, uint32_t *registration_id)
    {
        identity_store_data *data = (identity_store_data*)user_data;
        *registration_id = data->local_registration_id;
        return 0;
    }

    int identity_key_store_save_identity2(const char *name, size_t name_len, uint8_t *key_data, size_t key_len, void *user_data)
    {
        identity_store_data *data = (identity_store_data*)user_data;

        identity_store_key *s;

        signal_buffer *key_buf = signal_buffer_create(key_data, key_len);
        if(!key_buf) {
            return SG_ERR_NOMEM;
        }

        int64_t recipient_hash = jenkins_hash2(name, name_len);

        HASH_FIND(hh, data->keys, &recipient_hash, sizeof(int64_t), s);
        if(s) {
            signal_buffer_free(s->identity_key);
            s->identity_key = key_buf;
        }
        else {
            s = (identity_store_key*)malloc(sizeof(identity_store_key));
            if(!s) {
                signal_buffer_free(key_buf);
                return SG_ERR_NOMEM;
            }
            memset(s, 0, sizeof(identity_store_key));
            s->recipient_id = recipient_hash;
            s->identity_key = key_buf;
            HASH_ADD(hh, data->keys, recipient_id, sizeof(int64_t), s);
        }

        return 0;
    }

    int identity_key_store_is_trusted_identity2(const char *name, size_t name_len, uint8_t *key_data, size_t key_len, void *user_data)
    {
        identity_store_data *data = (identity_store_data*)user_data;

        int64_t recipient_hash = jenkins_hash2(name, name_len);

        identity_store_key *s;
        HASH_FIND(hh, data->keys, &recipient_hash, sizeof(int64_t), s);

        if(s) {
            uint8_t *store_data = signal_buffer_data(s->identity_key);
            size_t store_len = signal_buffer_len(s->identity_key);
            if(store_len != key_len) {
                return 0;
            }
            if(memcmp(key_data, store_data, key_len) == 0) {
                return 1;
            }
            else {
                return 0;
            }
        }
        else {
            return 1;
        }
    }

    void identity_key_store_destroy2(void *user_data)
    {
        identity_store_data *data = (identity_store_data*)user_data;

        identity_store_key *cur_node;
        identity_store_key *tmp_node;
        HASH_ITER(hh, data->keys, cur_node, tmp_node) {
            HASH_DEL(data->keys, cur_node);
            signal_buffer_free(cur_node->identity_key);
            free(cur_node);
        }
        signal_buffer_free(data->identity_key_public);
        signal_buffer_free(data->identity_key_private);
        free(data);
    }

    void setup_identity_key_store2(signal_protocol_store_context *context, signal_context *global_context)
    {
        identity_store_data *data = (identity_store_data*)malloc(sizeof(identity_store_data));
        memset(data, 0, sizeof(identity_store_data));

        ec_key_pair *identity_key_pair_keys = 0;
        curve_generate_key_pair(global_context, &identity_key_pair_keys);

        ec_public_key *identity_key_public = ec_key_pair_get_public(identity_key_pair_keys);
        ec_private_key *identity_key_private = ec_key_pair_get_private(identity_key_pair_keys);

        ec_public_key_serialize(&data->identity_key_public, identity_key_public);
        ec_private_key_serialize(&data->identity_key_private, identity_key_private);
        SIGNAL_UNREF(identity_key_pair_keys);

        data->local_registration_id = (rand() % 16380) + 1;

        signal_protocol_identity_key_store store = {
                .get_identity_key_pair = identity_key_store_get_identity_key_pair2,
                .get_local_registration_id = identity_key_store_get_local_registration_id2,
                .save_identity = identity_key_store_save_identity2,
                .is_trusted_identity = identity_key_store_is_trusted_identity2,
                .destroy_func = identity_key_store_destroy2,
                .user_data = data
        };

        signal_protocol_store_context_set_identity_key_store(context, &store);
    }

    /*------------------------------------------------------------------------*/

    typedef struct {
        int64_t group_id;
        int64_t recipient_id;
        int32_t device_id;
    } sender_key_store_key;

    typedef struct {
        sender_key_store_key key;
        signal_buffer *record;
        UT_hash_handle hh;
    } sender_key_store_record;

    typedef struct {
        sender_key_store_record *records;
    } sender_key_store_data;

    int sender_key_store_store_sender_key2(const signal_protocol_sender_key_name *sender_key_name, uint8_t *record, size_t record_len, void *user_data)
    {
        sender_key_store_data *data = (sender_key_store_data*)user_data;

        sender_key_store_record *s;

        sender_key_store_record l;
        memset(&l, 0, sizeof(sender_key_store_record));
        l.key.group_id = jenkins_hash2(sender_key_name->group_id, sender_key_name->group_id_len);
        l.key.recipient_id = jenkins_hash2(sender_key_name->sender.name, sender_key_name->sender.name_len);
        l.key.device_id = sender_key_name->sender.device_id;

        signal_buffer *record_buf = signal_buffer_create(record, record_len);
        if(!record_buf) {
            return SG_ERR_NOMEM;
        }

        HASH_FIND(hh, data->records, &l.key, sizeof(sender_key_store_key), s);

        if(s) {
            signal_buffer_free(s->record);
            s->record = record_buf;
        }
        else {
            s = (sender_key_store_record*)malloc(sizeof(sender_key_store_record));
            if(!s) {
                signal_buffer_free(record_buf);
                return SG_ERR_NOMEM;
            }
            memset(s, 0, sizeof(sender_key_store_record));
            s->key.group_id = jenkins_hash2(sender_key_name->group_id, sender_key_name->group_id_len);
            s->key.recipient_id = jenkins_hash2(sender_key_name->sender.name, sender_key_name->sender.name_len);
            s->key.device_id = sender_key_name->sender.device_id;
            s->record = record_buf;
            HASH_ADD(hh, data->records, key, sizeof(sender_key_store_key), s);
        }

        return 0;
    }

    int sender_key_store_load_sender_key2(signal_buffer **record, const signal_protocol_sender_key_name *sender_key_name, void *user_data)
    {
        sender_key_store_data *data = (sender_key_store_data*)user_data;

        sender_key_store_record *s;

        sender_key_store_record l;
        memset(&l, 0, sizeof(session_store_session));
        l.key.group_id = jenkins_hash2(sender_key_name->group_id, sender_key_name->group_id_len);
        l.key.recipient_id = jenkins_hash2(sender_key_name->sender.name, sender_key_name->sender.name_len);
        l.key.device_id = sender_key_name->sender.device_id;
        HASH_FIND(hh, data->records, &l.key, sizeof(sender_key_store_key), s);

        if(!s) {
            return 0;
        }
        signal_buffer *result = signal_buffer_copy(s->record);
        if(!result) {
            return SG_ERR_NOMEM;
        }
        *record = result;
        return 1;
    }

    void sender_key_store_destroy2(void *user_data)
    {
        sender_key_store_data *data = (sender_key_store_data*)user_data;

        sender_key_store_record *cur_node;
        sender_key_store_record *tmp_node;
        HASH_ITER(hh, data->records, cur_node, tmp_node) {
            HASH_DEL(data->records, cur_node);
            signal_buffer_free(cur_node->record);
            free(cur_node);
        }
        free(data);
    }

    void setup_sender_key_store2(signal_protocol_store_context *context, signal_context *global_context)
    {
        sender_key_store_data *data = (sender_key_store_data*)malloc(sizeof(sender_key_store_data));
        memset(data, 0, sizeof(sender_key_store_data));

        signal_protocol_sender_key_store store = {
            .store_sender_key = sender_key_store_store_sender_key2,
            .load_sender_key = sender_key_store_load_sender_key2,
            .destroy_func = sender_key_store_destroy2,
            .user_data = data
        };

        signal_protocol_store_context_set_sender_key_store(context, &store);
    }
   
