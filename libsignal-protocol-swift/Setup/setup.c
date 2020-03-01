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

char* decryptMsgMethod(const char* encryptMsg,const char* senderName,const char* decode_content,const char* decode_key){
   return decryptMessage2(encryptMsg, senderName,decode_content,decode_key);
}


