//
//  SignatureSubpacketTypes.swift
//  PGPFormat
//
//  Created by Alex Grinman on 5/19/17.
//  Copyright © 2017 KryptCo, Inc. All rights reserved.
//

import Foundation


// MARK: Created Time
public struct SignatureCreated:SignatureSubpacketable {
    public var type:SignatureSubpacketType {
        return .created
    }
    
    public var date:Date
    
    public enum SignatureCreatedError:Error {
        case invalidBodyLength(Int)
    }
    
    public init(date:Date) {
        self.date = date
    }
    
    public init(packet:SignatureSubpacket) throws {
        guard packet.header.subpacketType == .created else {
            throw SignatureSubpacketableError.invalidSubpacketType(packet.header.subpacketType)
        }
        
        guard packet.body.count == 4 else {
            throw SignatureCreatedError.invalidBodyLength(packet.body.count)
        }
        
        
        let creationSeconds = Double(UInt32(bigEndianBytes: [UInt8](packet.body.bytes[0 ... 3])))
        date = Date(timeIntervalSince1970: creationSeconds)
    }
    
    public func toData() throws -> Data {
        return Data(bytes: UInt32(date.timeIntervalSince1970).fourByteBigEndianBytes())
    }
}

// MARK: Issuer
public struct SignatureIssuer:SignatureSubpacketable, CustomDebugStringConvertible {
    public var type:SignatureSubpacketType {
        return .issuer
    }
    
    public var keyID:Data
    
    public enum SignatureIssuer:Error {
        case invalidBodyLength(Int)
    }
    
    public init(keyID:Data) {
        self.keyID = keyID
    }
    
    public init(packet:SignatureSubpacket) throws {
        guard packet.header.subpacketType == .issuer else {
            throw SignatureSubpacketableError.invalidSubpacketType(packet.header.subpacketType)
        }
        
        guard packet.body.count == 8 else {
            throw SignatureIssuer.invalidBodyLength(packet.body.count)
        }
        
        keyID = Data(packet.body.subdata(in: 0 ..< 8))
    }
    
    public func toData() throws -> Data {
        return keyID
    }
    
    
    public var debugDescription:String {
        return keyID.hex.uppercased()
    }
}

// MARK: Key Flags
public enum KeyFlagType:UInt8 {
    case certifyOtherKeys       = 0x01
    case signData               = 0x02
    case encryptCommunication   = 0x04
    case encryptStorage         = 0x08
    case splitKey               = 0x10
    case authentication         = 0x20
    case ownedBySeveral         = 0x80
}

public struct SignatureKeyFlags:SignatureSubpacketable, CustomDebugStringConvertible {
    public var type:SignatureSubpacketType {
        return .keyFlags
    }
    
    public var flags:[KeyFlagType]
    public var unknowns:[UInt8]
    
    public enum SignatureIssuer:Error {
        case invalidBodyLength(Int)
    }
    
    public init(flagTypes:[KeyFlagType]) {
        flags = flagTypes
        unknowns = []
    }
    
    public init(packet:SignatureSubpacket) throws {
        guard packet.header.subpacketType == .keyFlags else {
            throw SignatureSubpacketableError.invalidSubpacketType(packet.header.subpacketType)
        }
        
        flags = []
        unknowns = []
        
        for byte in packet.body.bytes {
            guard let flag = KeyFlagType(rawValue: byte) else {
                unknowns.append(byte)
                continue
            }
            
            flags.append(flag)
        }
    }
    
    public func toData() throws -> Data {
        var data = Data(bytes: flags.map({ $0.rawValue }))
        data.append(contentsOf: unknowns)
        
        return data
    }
    
    public var debugDescription:String {
        return "Key Flags: \(flags)"
    }
}

// MARK: Key Expiration Time
public struct SignatureKeyExpires:SignatureSubpacketable {
    public var type:SignatureSubpacketType {
        return .keyExpires
    }
    
    public var date:Date
    
    public enum SignatureKeyExpires:Error {
        case invalidBodyLength(Int)
    }
    
    public init(packet:SignatureSubpacket) throws {
        guard packet.header.subpacketType == .keyExpires else {
            throw SignatureSubpacketableError.invalidSubpacketType(packet.header.subpacketType)
        }
        
        guard packet.body.count == 4 else {
            throw SignatureKeyExpires.invalidBodyLength(packet.body.count)
        }
        
        
        let expirationSeconds = Double(UInt32(bigEndianBytes: [UInt8](packet.body.bytes[0 ... 3])))
        date = Date(timeIntervalSince1970: expirationSeconds)
    }
    
    public func toData() throws -> Data {
        return Data(bytes: UInt32(date.timeIntervalSince1970).fourByteBigEndianBytes())
    }
}

// MARK: A Default Subpacket
public struct SignatureUnparsedSubpacket:SignatureSubpacketable {
    public var type:SignatureSubpacketType
    public var body:Data
    
    public init(packet:SignatureSubpacket) throws {
        self.type = packet.header.subpacketType
        self.body = packet.body
    }
    
    public func toData() throws -> Data {
        return body
    }
}

