//
//  UserID.swift
//  PGPFormat
//
//  Created by Alex Grinman on 5/15/17.
//  Copyright © 2017 KryptCo, Inc. All rights reserved.
//


import Foundation


public struct UserID:Packetable {
    
    public var tag:PacketTag {
        return .userID
    }

    public var name:String?
    public var email:String?
    
    public var content:String
    
    public init(packet:Packet) throws {
        guard packet.header.tag == .userID else {
            throw PacketableError.invalidPacketTag(packet.header.tag)
        }
        
        guard let all = String(data: packet.body, encoding: .utf8)
        else {
            throw FormatError.encoding
        }
        
        self.content = all
        setNameAndEmail()
    }
    
    public func toData() throws -> Data {
        guard let data = content.data(using: .utf8) else {
            throw FormatError.encoding
        }
        
        return data
    }

    mutating private func setNameAndEmail() {
        let components = content.components(separatedBy: "<")
        guard components.count >= 2 else {
            return
        }
        
        self.name = components[0].trimmingCharacters(in: CharacterSet.whitespaces)
        self.email = components[1].replacingOccurrences(of: ">", with: "").trimmingCharacters(in: CharacterSet.whitespaces)
    }
}

