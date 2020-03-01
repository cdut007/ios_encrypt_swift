//
//  Signal.swift
//  libsignal-protocol-swift iOS
//
//  Created by User on 15.02.18.
//  Copyright © 2018 User. All rights reserved.
//

import Foundation
import SignalModule

/**
 Main entry point for initialization of a client.
 */
public final class Signal {

    private static let def = Signal()

    static var context: OpaquePointer {
        return def.globalContext!
    }

    private var globalContext: OpaquePointer?

    init() {
//        guard let con = signal_setup() else {
//            fatalError("Could not create global signal context")
//        }
//        self.globalContext = OpaquePointer(con)
       
    }

    deinit {
        //let ptr = UnsafeMutableRawPointer(globalContext)
       // signal_destroy(ptr)
    }
}

public extension Signal {

   static private func convertUtf8Str(_ text:String)->UnsafePointer<Int8>?{
        
        let nsStr = text as NSString
        let cstr =   nsStr.utf8String
        return cstr
    }
    static private func makeCString(from str: String) -> UnsafeMutablePointer<Int8> {
        let count = str.utf8.count + 1
        let result = UnsafeMutablePointer<Int8>.allocate(capacity: count)
        str.withCString { (baseAddress) in
            // func initialize(from: UnsafePointer<Pointee>, count: Int)
            result.initialize(from: baseAddress, count: count)
        }
        return result
    }
    
    
    static func encryptMessage(currentUser:String,receiverName:String, orignalMsg:String) -> String{
        
         let info = SignalProtocol.encryptMsgMethod(convertUtf8Str(currentUser),convertUtf8Str(receiverName),convertUtf8Str(orignalMsg))
         let encryptedMsg =  String(cString: info!)
        print("\(encryptedMsg)")
        
        return encryptedMsg
      }
    
    static func decryptMessage(encryptMsg:String,senderName:String) -> String{
    
        let index = encryptMsg.range(of: ".")!.lowerBound;
        let decode_msg_content  = String(encryptMsg[..<index]);
        let pos = index.utf16Offset(in: encryptMsg)+2;
        let decode_session_key  = String(encryptMsg.suffix(encryptMsg.count-pos));

            let info = SignalProtocol.decryptMsgMethod(convertUtf8Str(encryptMsg),convertUtf8Str(senderName),convertUtf8Str(decode_msg_content),convertUtf8Str(decode_session_key))
            let decryptMsg =  String(cString: info!)
           print("\(decryptMsg)")
           
           return decryptMsg
         }
       
    
    
   
}
