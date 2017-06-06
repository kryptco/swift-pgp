//
//  Message.swift
//  PGPFormat
//
//  Created by Alex Grinman on 5/29/17.
//  Copyright © 2017 KryptCo, Inc. All rights reserved.
//

import Foundation

/** 
    A PGP Message is a sequence of Packets.
 */
public struct Message {
    let packets:[Packet]
    
    public func data() -> Data {
        var packetData = Data()
        packets.forEach {
            packetData.append($0.toData())
        }
        
        return packetData
    }
    
    public init (packets:[Packet]) {
        self.packets = packets
    }
    
    public init(data:Data) throws {
        try self.init(packets: [Packet](data: data))
    }
    
    public init(base64:String) throws {
        try self.init(data: base64.fromBase64())
    }
    
    public func armoredMessage(blockType:ArmorMessageBlock, comment:String? = nil) -> AsciiArmorMessage {
        return AsciiArmorMessage(message: self, blockType: blockType, comment: comment)
    }
}
