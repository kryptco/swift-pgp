//
//  Signature.swift
//  PGPFormat
//
//  Created by Alex Grinman on 5/15/17.
//  Copyright © 2017 KryptCo, Inc. All rights reserved.
//


import Foundation


/**
    https://tools.ietf.org/html/rfc4880
    Section 5.2.1
*/
public struct Signature:Packetable {
    
    public var tag:PacketTag {
        return .signature
    }
    
    public enum Kind:UInt8 {
        case binaryDocument = 0
        case subKey = 18
        case primaryKey = 19
        
        init(type:UInt8) throws {
            guard let sigType = Kind(rawValue: type) else {
                throw ParsingError.unsupportedSignatureType(type)
            }
            self = sigType
        }
    }
    
    /**
        https://tools.ietf.org/html/rfc4880
        Section 9.4
    */
    public enum HashAlgorithm:UInt8 {
        case sha1   = 2
        case sha256 = 8
        case sha384 = 9
        case sha512 = 10
        case sha224 = 11
        
        init(type:UInt8) throws {
            guard let algo = HashAlgorithm(rawValue: type) else {
                throw ParsingError.unsupportedHashAlgorithm(type)
            }
            
            self = algo
        }
    }
    
    public enum ParsingError:Error {
        case unsupportedSignatureType(UInt8)
        case unsupportedVersion(UInt8)
        case unsupportedHashAlgorithm(UInt8)
    }
    
    public enum SerializingError:Error {
        case tooManySubpackets
        case signatureTooShort
    }

    
    
    /**
        Signature Properties
    */
    public let supportedVersion = 4
    
    public var kind:Kind
    public var publicKeyAlgorithm:PublicKeyAlgorithm
    public var hashAlgorithm:HashAlgorithm
    
    public var hashedSubpackets:[SignatureSubpacket]
    public var unhashedSubpackets:[SignatureSubpacket]
    
    public var signature:Data

    public init(packet:Packet) throws {
        guard packet.header.tag == .signature else {
            throw PacketableError.invalidPacketTag(packet.header.tag)
        }

        let data = packet.body
        
        guard data.count >= 6 else {
            throw FormatError.tooShort(data.count)
        }
        
        let bytes = data.bytes
        
        guard Int(bytes[0]) == supportedVersion else {
            throw ParsingError.unsupportedVersion(bytes[0])
        }
        
        kind                = try Kind(type: bytes[1])
        publicKeyAlgorithm  = try PublicKeyAlgorithm(type: bytes[2])
        hashAlgorithm       = try HashAlgorithm(type: bytes[3])
        
        
        // hashed subpackets
        let hashedDataLength = Int(UInt32(bigEndianBytes: [UInt8](bytes[4 ... 5])))
        
        var ptr = 6
        guard bytes.count >= ptr + hashedDataLength else {
            throw FormatError.tooShort(bytes.count)
        }
        
        hashedSubpackets = try [SignatureSubpacket](data: Data(bytes: bytes[ptr ..< (ptr + hashedDataLength)]))
        
        ptr += hashedDataLength

        // unhashed subpackets
        guard bytes.count >= ptr + 2 else {
            throw FormatError.tooShort(bytes.count)
        }
        
        let unhashedDataLength = Int(UInt32(bigEndianBytes: [UInt8](bytes[ptr ... ptr + 1])))
        ptr += 2
        
        guard bytes.count >= ptr + unhashedDataLength else {
            throw FormatError.tooShort(bytes.count)
        }
        
        unhashedSubpackets = try [SignatureSubpacket](data: Data(bytes: bytes[ptr ..< (ptr + unhashedDataLength)]))
        ptr += unhashedDataLength
        
        
        // left 16 bits of signed hash
        // guard bytes.count >= ptr + 2 else {
        //    throw FormatError.tooShort(bytes.count)
        // }
        
        // ignoring
        // _ = [UInt8](bytes[ptr ... (ptr + 1)])
        
        // signature MPI
        switch publicKeyAlgorithm {
        case .rsaEncryptOrSign, .rsaSignOnly:
            ptr += 2 // skip two-octets for left 16 bits of sig
            
            guard bytes.count >= ptr + 2 else {
                throw FormatError.tooShort(bytes.count)
            }
            
            let signatureLength = Int(UInt32(bigEndianBytes: [UInt8](bytes[ptr ... ptr + 1])) + 7)/8
            ptr += 2
            
            guard bytes.count >= ptr + signatureLength else {
                throw FormatError.tooShort(bytes.count)
            }
            
            signature = Data(bytes: bytes[ptr ..< (ptr + signatureLength)])

        default:
            throw UnsupportedPublicKeyAlgorithm(type: publicKeyAlgorithm.rawValue)
            
        }

    }
    
    public func toData() throws -> Data {
        var data = Data()
        
        data.append(contentsOf: [UInt8(supportedVersion)])
        data.append(contentsOf: [kind.rawValue])
        data.append(contentsOf: [publicKeyAlgorithm.rawValue])
        data.append(contentsOf: [hashAlgorithm.rawValue])
        
        // hashed subpackets
        let hashedSubpacketLength = hashedSubpackets.reduce(0, { $0 + $1.length })
        guard hashedSubpacketLength <= Int(UInt32.max) else {
            throw SerializingError.tooManySubpackets
        }
        // length
        data.append(contentsOf: UInt32(hashedSubpacketLength).twoByteBigEndianBytes())
        // data
        try hashedSubpackets.forEach {
            data.append(try $0.toData())
        }
        
        // un-hashed subpackets
        let unhashedSubpacketLength = unhashedSubpackets.reduce(0, { $0 + $1.length })
        guard unhashedSubpacketLength <= Int(UInt32.max) else {
            throw SerializingError.tooManySubpackets
        }
        // length
        data.append(contentsOf: UInt32(unhashedSubpacketLength).twoByteBigEndianBytes())
        // data
        try unhashedSubpackets.forEach {
            data.append(try $0.toData())
        }
        
        // left 16 bits
        guard signature.count >= 2 else {
            throw SerializingError.signatureTooShort
        }
        data.append(signature.subdata(in: 0 ..< 2))

        
        // signature MPI
        data.append(contentsOf: UInt32(signature.numBits).twoByteBigEndianBytes())
        data.append(signature)
        
        return data
    }

}


