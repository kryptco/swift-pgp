//
//  OnePassSignature.swift
//  PGPFormat
//
//  Created by Alex Grinman on 6/20/17.
//  Copyright © 2017 KryptCo, Inc. All rights reserved.
//

import Foundation


/**
    A One Pass Signature packet
    https://tools.ietf.org/html/rfc4880#section-5.4
 */
public struct OnePassSignature:Packetable {
    
    public var tag:PacketTag {
        return .onePassSignature
    }
    
    public enum ParsingError:Error {
        case unsupportedVersion(UInt8)
        case unsupportedNestedFlag(UInt8)
    }
    
    public let supportedVersion = 3
    public var kind:Signature.Kind
    public var hashAlgorithm:Signature.HashAlgorithm
    public var publicKeyAlgorithm:PublicKeyAlgorithm
    public var keyID:Data
    public let nestedFlag:UInt8 = 1
    
    public init(packet:Packet) throws {
        guard packet.header.tag == .onePassSignature else {
            throw PacketableError.invalidPacketTag(packet.header.tag)
        }
        
        let data = packet.body
        
        guard data.count >= 4 else {
            throw DataError.tooShort(data.count)
        }
        
        let bytes = data.bytes
        
        guard Int(bytes[0]) == supportedVersion else {
            throw ParsingError.unsupportedVersion(bytes[0])
        }
        
        kind                = try Signature.Kind(type: bytes[1])
        hashAlgorithm       = try Signature.HashAlgorithm(type: bytes[2])
        publicKeyAlgorithm  = try PublicKeyAlgorithm(type: bytes[3])
        
        // the byte pointer
        var ptr = 4

        // 8-byte key id
        guard data.count >= ptr + 8 else {
            throw DataError.tooShort(data.count)
        }
        
        keyID = Data(bytes[ptr ..< ptr + 8])
        ptr += 8
        
        guard data.count >= ptr + 1 else {
            throw DataError.tooShort(data.count)
        }

        let nested = bytes[ptr]
        guard nested == nestedFlag else {
            throw ParsingError.unsupportedNestedFlag(nested)
        }
    }
    
    init(signature:Signature, keyID:Data) {
        self.kind = signature.kind
        self.hashAlgorithm = signature.hashAlgorithm
        self.publicKeyAlgorithm = signature.publicKeyAlgorithm
        self.keyID = keyID
    }
    
    public func toData() throws -> Data {
        var data = Data()
        
        data.append(contentsOf: [UInt8(supportedVersion)])
        data.append(contentsOf: [kind.rawValue])
        data.append(contentsOf: [hashAlgorithm.rawValue])
        data.append(contentsOf: [publicKeyAlgorithm.rawValue])
        data.append(contentsOf: keyID.bytes)
        data.append(contentsOf: [nestedFlag])

        return data
    }

}


