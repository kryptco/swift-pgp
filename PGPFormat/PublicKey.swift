//
//  PublicKey.swift
//  PGPFormat
//
//  Created by Alex Grinman on 5/15/17.
//  Copyright © 2017 KryptCo, Inc. All rights reserved.
//


import Foundation

/**
    Supported Public Key Algorithm Types
    Full list: https://tools.ietf.org/html/rfc4880#section-9.1
    + Ed25519: https://tools.ietf.org/html/draft-koch-eddsa-for-openpgp-00
 */
public enum PublicKeyAlgorithm:UInt8 {
    case rsaEncryptOrSign = 1
    case rsaEncryptOnly = 2
    case rsaSignOnly = 3
    case ed25519 = 22
    
    init(type:UInt8) throws {
        guard let algo = PublicKeyAlgorithm(rawValue: type) else {
            throw UnsupportedType(type: type)
        }
        
        self = algo
    }
    
    public struct UnsupportedType:Error {
        var type:UInt8
    }
}


/**
    A Public Key packet
 */
public struct PublicKey:Packetable {
    
    /**
        Only supports version 4
     */
    private let supportedVersion = 4
    
    public let tag:PacketTag
    
    public var created:Date
    public var algorithm:PublicKeyAlgorithm
    public var publicKeyData:PublicKeyData
    
    /**
        Public key packet parsing error
     */
    public enum ParsingError:Error {
        case tooShort(Int)
        case unsupportedVersion(UInt8)
        case invalidFinerprintLength(Int)
    }
    
    public init(create algorithm:PublicKeyAlgorithm, publicKeyData:PublicKeyData, date:Date = Date()) {
        self.tag = .publicKey
        self.algorithm = algorithm
        self.publicKeyData = publicKeyData
        self.created = date
    }
    
    /**
        Initialize a Public Key from a packet
     */
    public init(packet:Packet) throws {
        
        // get packet tag, ensure it's a public key type
        switch packet.header.tag {
        case .publicKey, .publicSubkey:
            self.tag = packet.header.tag
        default:
            throw PacketableError.invalidPacketTag(packet.header.tag)
        }
        
        // parse the body
        let data = packet.body
        
        guard data.count > 6 else {
            throw DataError.tooShort(data.count)
        }
        
        let bytes = data.bytes
        
        // version (0)
        guard Int(bytes[0]) == supportedVersion else {
            throw ParsingError.unsupportedVersion(bytes[0])
        }
        
        // created (1 ..< 5)
        let creationSeconds = Double(UInt32(bigEndianBytes: [UInt8](bytes[1 ..< 5])))
        created = Date(timeIntervalSince1970: creationSeconds)
        
        // algo (5)
        algorithm = try PublicKeyAlgorithm(type: bytes[5])
        
        // parse the key data
        let keyData = Data(bytes: bytes[6 ..< bytes.count])
        
        switch algorithm {
        case .rsaSignOnly, .rsaEncryptOnly, .rsaEncryptOrSign:
            self.publicKeyData = try RSAPublicKey(mpintData: keyData)
            
        case .ed25519:
            self.publicKeyData = try Ed25519PublicKey(mpintData: keyData)
        }
    }
    
    /** 
        Serialize public key to packet body data
     */
    public func toData() -> Data {
        
        var data = Data()
        
        // add supported version
        data.append(contentsOf: [UInt8(supportedVersion)])
        
        // add created time
        data.append(contentsOf: UInt32(created.timeIntervalSince1970).fourByteBigEndianBytes())
        
        // add algorithm
        data.append(contentsOf: [algorithm.rawValue])
        
        // add public key data
        data.append(publicKeyData.toData())
        
        return data
    }

    /**
        Compute the SHA1 fingerprint of the public key
        https://tools.ietf.org/html/rfc4880#section-12.2
     */
    public func fingerprint() -> Data {
        var dataToHash = Data()
        dataToHash.append(contentsOf: [0x99])
        
        // pubkey length + data
        let publicKeyPacketData = self.toData()
        let pubKeyLengthBytes = UInt32(publicKeyPacketData.count).twoByteBigEndianBytes()
        dataToHash.append(contentsOf: pubKeyLengthBytes)
        dataToHash.append(publicKeyPacketData)
        
        return dataToHash.SHA1
    }

    /**
        Compute the KeyID of a public key from its fingerprint
     */
    public func keyID() throws -> Data {
        let fingerprint = self.fingerprint()
        
        guard fingerprint.count == 20 else {
            throw ParsingError.invalidFinerprintLength(fingerprint.count)
        }
        
        return Data(bytes: fingerprint.bytes[12 ..< 20])
    }
}


