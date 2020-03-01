//
//  setup.c
//  libsignal-protocol-swift iOS
//
//  Created by User on 15.02.18.
//  Copyright © 2018 User. All rights reserved.
//

#include "setup.h"
#include "encrypt_common.h"



char* encryptMsgMethod(const char* currentUser,const char* receiverName, const char* orignalMsg){
   return encryptMsg2(currentUser, receiverName, orignalMsg);
}




void decryptMessage(const char* encryptMsg,int encryptMsgLen, const char* senderName,int senderNameLen){
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
//                std::string decode_content,decode_key;
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
//              fprintf(stderr,"find session decode_content:" << decode_content << "\n decode_key:" << decode_key;
//                /* Deserialize the record */
//                std::string decode_content_origal,decode_key_origal;
//                decode_content_origal = base64_decode(decode_content);
//                decode_key_origal = base64_decode(decode_key);
//
//                session_record *record_deserialized = 0;
//                const char*  expr_session_record= decode_key_origal.c_str();
//                uint8_t * data = (uint8_t *)expr_session_record;
//
//
//                int len = decode_key_origal.size();
//
//                result = session_record_deserialize(&record_deserialized, data, len, global_context);
//               fprintf(stderr,"find session decode_key_len :" << len;
//                bob_session_record = record_deserialized;
//
//
//        signal_protocol_address bob_address = {
//                                senderName.c_str(), senderName.size(), 1
//                        };
//        /* Create the  data store */
//        signal_protocol_store_context *bob_store = 0;
//        setup_store_context2(&bob_store, global_context);
//        /* Store the  session in their data store */
//        result = signal_protocol_session_store_session(bob_store, &bob_address, bob_session_record);
//        /* Create  session cipher instance */
//        session_cipher *bob_cipher = 0;
//        result = session_cipher_create(&bob_cipher, bob_store, &bob_address, global_context);
//
//
//        int decryptlen = decode_content_origal.size();
//        const char*  expr= decode_content_origal.c_str();
//        uint8_t * message = (uint8_t *)expr;
//        size_t alice_plain_content_len = decryptlen;
//        fprintf(stderr," decrypt alice_plain_content_len,result:%d",alice_plain_content_len);
//        signal_message *alice_message_deserialized = 0;
//        result = signal_message_deserialize(&alice_message_deserialized,
//                message,
//                alice_plain_content_len,
//                global_context);
//        fprintf(stderr,"signal_message_deserialize,result:%d",result);
//        /* Have Bob decrypt the test message */
//        signal_buffer *bob_plaintext = 0;
//        result = session_cipher_decrypt_signal_message(bob_cipher, alice_message_deserialized, 0, &bob_plaintext);
//        ////ck_assert_int_eq(result, 0);
//       fprintf(stderr,"session_cipher_decrypt_signal_message,result:%d",result);
//
//        uint8_t *bob_plaintext_data = signal_buffer_data(bob_plaintext);
//        size_t bob_plaintext_len = signal_buffer_len(bob_plaintext);
//
//        /* in case you'd expect char buffer, just a byte to byte copy */
//        std::string decrypt_info((char*)bob_plaintext_data, bob_plaintext_len);
//        encryptMsg = decrypt_info;
//        fprintf(stderr,"session_cipher_decrypt_signal_message,content"<<encryptMsg;
//        //ck_assert_int_eq(memcmp(alice_plaintext, bob_plaintext_data, bob_plaintext_len), 0);
//        fprintf(stderr,"Interaction complete: Alice -> Bob\n");
//
//        SIGNAL_UNREF(alice_message_deserialized);
//        signal_buffer_free(bob_plaintext);
//        session_cipher_free(bob_cipher);
//        signal_protocol_store_context_destroy(bob_store);
//        /* Cleanup */
//        //SIGNAL_UNREF(alice_session_record);
//        SIGNAL_UNREF(bob_session_record);
//        signal_destroy(global_context);
}


