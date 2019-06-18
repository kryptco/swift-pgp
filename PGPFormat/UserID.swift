//
//  UserID.swift
//  PGPFormat
//
//  Created by Alex Grinman on 5/15/17.
//  Copyright © 2017 KryptCo, Inc. All rights reserved.
//


import Foundation

/**
    A UserID packet
    https://tools.ietf.org/html/rfc4880#section-5.11
 */
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
            throw DataError.encoding
        }
        
        self.init(content: all)
    }
    
    public init(name:String, email:String) {
        self.name = name
        self.email = email
        self.content = "\(name) <\(email)>"
    }
    
    public init(content:String) {
        self.content = content
        setNameAndEmail()
    }

    
    public func toData() -> Data {
        return Data([UInt8](content.utf8))
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

