//
//  setup.h
//  libsignal-protocol-swift iOS
//
//  Created by User on 15.02.18.
//  Copyright © 2018 User. All rights reserved.
//

#ifndef setup_h
#define setup_h








char* encryptMsgMethod(const char* currentUser,const char* receiverName, const char* orignalMsg);
char* decryptMsgMethod(const char* encryptMsg,const char* senderName,const char* decode_content,const char* decode_key);

#endif /* setup_h */
