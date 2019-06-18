//
//  SignatureSubpacketTypes.swift
//  PGPFormat
//
//  Created by Alex Grinman on 5/19/17.
//  Copyright © 2017 KryptCo, Inc. All rights reserved.
//

import Foundation


/**
    Represents possible Signature Subpacket types
    https://tools.ietf.org/html/rfc4880#section-5.2.3.1
 */
public enum SignatureSubpacketType:UInt8 {
    case created        = 2
    case keyExpires     = 9
    case issuer         = 16
    case keyFlags       = 27
    
    // not handeled specifically
    case sigExpires                     = 3
    case trust                          = 5
    case preferedSymmetricKeyAlgorithms = 11
    case preferedHashAlgorithms         = 21
    case preferedCompressionAlgorithms  = 22
    case keyServer                      = 23
    case preferedKeyServer              = 24
    case primaryUserID                  = 25
    case features                       = 30
    
    case issuerFingerprint              = 33
    
    init(type:UInt8) throws {
        guard let sigType = SignatureSubpacketType(rawValue: type) else {
            throw SignatureSubpacketError.unsupportedType(type)
        }
        
        self = sigType
    }
    
}

/**
    Signature Creation Time
    https://tools.ietf.org/html/rfc4880#section-5.2.3.4
 */
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
        return Data(UInt32(date.timeIntervalSince1970).fourByteBigEndianBytes())
    }
}

/**
    Signature Issuer
    https://tools.ietf.org/html/rfc4880#section-5.2.3.5
 */
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

/**
    Signature Key Expiration Time
    https://tools.ietf.org/html/rfc4880#section-5.2.3.6
 */
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
        return Data(UInt32(date.timeIntervalSince1970).fourByteBigEndianBytes())
    }
}

/**
    Signature Issuer Fingerprint
 */
public struct SignatureIssuerFingerprint:SignatureSubpacketable {
    public var type:SignatureSubpacketType {
        return .issuerFingerprint
    }
    
    public var fingerprint:Data
    
    public init(fingerprint:Data) {
        self.fingerprint = fingerprint
    }
    
    public init(packet:SignatureSubpacket) throws {
        guard packet.header.subpacketType == .issuerFingerprint else {
            throw SignatureSubpacketableError.invalidSubpacketType(packet.header.subpacketType)
        }
        
        fingerprint = packet.body
    }
    
    public func toData() throws -> Data {
        return fingerprint
    }
}

/**
    Signature Key Flags
    https://tools.ietf.org/html/rfc4880#section-5.2.3.21
 */
public struct SignatureKeyFlags:SignatureSubpacketable, CustomDebugStringConvertible {
    public var type:SignatureSubpacketType {
        return .keyFlags
    }
    
    public enum FlagType:UInt8 {
        case certifyOtherKeys       = 0x01
        case signData               = 0x02
        case encryptCommunication   = 0x04
        case encryptStorage         = 0x08
        case splitKey               = 0x10
        case authentication         = 0x20
        case ownedBySeveral         = 0x80
    }
    
    public var flags:[FlagType]
    public var unknowns:[UInt8]
    
    public enum SignatureIssuer:Error {
        case invalidBodyLength(Int)
    }
    
    public init(flagTypes:[FlagType]) {
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
            guard let flag = FlagType(rawValue: byte) else {
                unknowns.append(byte)
                continue
            }
            
            flags.append(flag)
        }
    }
    
    public func toData() throws -> Data {
        var data = Data(flags.map({ $0.rawValue }))
        data.append(contentsOf: unknowns)
        
        return data
    }
    
    public var debugDescription:String {
        return "Key Flags: \(flags)"
    }
}

/** 
    A default signature subpacket
 */
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

