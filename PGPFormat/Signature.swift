//
//  Signature.swift
//  PGPFormat
//
//  Created by Alex Grinman on 5/15/17.
//  Copyright © 2017 KryptCo, Inc. All rights reserved.
//


import Foundation


/**
    A Signature packet
    https://tools.ietf.org/html/rfc4880#section-5.2
 */
public struct Signature:Packetable {
    
    public var tag:PacketTag {
        return .signature
    }
    
    /**
        The type of signature
        https://tools.ietf.org/html/rfc4880#section-5.2.1
     */
    public enum Kind:UInt8 {
        case binaryDocument = 0x00
        case userID = 0x10
        case personalUserID = 0x11
        case casualUserID = 0x12
        case positiveUserID = 0x13
        case subKey = 0x18
        case primaryKey = 0x19
        
        init(type:UInt8) throws {
            guard let sigType = Kind(rawValue: type) else {
                throw ParsingError.unsupportedSignatureType(type)
            }
            self = sigType
        }
    }
    
    /**
        Signature Hash Algorithm
        https://tools.ietf.org/html/rfc4880#section-9.4
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
    
    /**
        Signature error types
     */
    public enum ParsingError:Error {
        case unsupportedSignatureType(UInt8)
        case unsupportedVersion(UInt8)
        case unsupportedHashAlgorithm(UInt8)
        case signatureHasExtraBytes(Int)
    }
    
    public enum SerializingError:Error {
        case tooManySubpackets
        case signatureTooShort
        case invalidSignatureLength(Int)
        case invalidHashLength(Int)
    }

    
    
    /**
        Only support version 4 signatures
    */
    public let supportedVersion = 4
    
    public var kind:Kind
    public var publicKeyAlgorithm:PublicKeyAlgorithm
    public var hashAlgorithm:HashAlgorithm
    public var hashedSubpacketables:[SignatureSubpacketable]
    public var unhashedSubpacketables:[SignatureSubpacketable]
    public var signature:[Data]
    public var leftTwoHashBytes:[UInt8]

    /**
        Initialize a signature from a packet
     */
    public init(packet:Packet) throws {
        guard packet.header.tag == .signature else {
            throw PacketableError.invalidPacketTag(packet.header.tag)
        }

        let data = packet.body
        
        guard data.count >= 6 else {
            throw DataError.tooShort(data.count)
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
            throw DataError.tooShort(bytes.count)
        }
        
        hashedSubpacketables = try [SignatureSubpacket](data: Data(bytes[ptr ..< (ptr + hashedDataLength)])).toSignatureSubpacketables()
        
        ptr += hashedDataLength

        // unhashed subpackets
        guard bytes.count >= ptr + 2 else {
            throw DataError.tooShort(bytes.count)
        }
        
        let unhashedDataLength = Int(UInt32(bigEndianBytes: [UInt8](bytes[ptr ... ptr + 1])))
        ptr += 2
        
        guard bytes.count >= ptr + unhashedDataLength else {
            throw DataError.tooShort(bytes.count)
        }
        
        unhashedSubpacketables = try [SignatureSubpacket](data: Data(bytes[ptr ..< (ptr + unhashedDataLength)])).toSignatureSubpacketables()
        ptr += unhashedDataLength
        
        
        // left 16 bits of signed hash
         guard bytes.count >= ptr + 2 else {
            throw DataError.tooShort(bytes.count)
         }
        
        // ignoring
        leftTwoHashBytes = [UInt8](bytes[ptr ... (ptr + 1)])
        
        ptr += 2 // jump two-octets for left 16 bits of sig

        guard bytes.count > ptr else {
            throw DataError.tooShort(bytes.count)
        }

        // signature MPI
        switch publicKeyAlgorithm {
        case .rsaEncryptOrSign, .rsaSignOnly:
            let signatureMPInt = try MPInt(mpintData: Data(bytes[ptr ..< bytes.count]))
            signature = [signatureMPInt.data]
            ptr += signatureMPInt.byteLength
            
        case .ed25519:
            // first point
            let firstPointMPInt = try MPInt(mpintData: Data(bytes[ptr ..< bytes.count]))

            ptr += firstPointMPInt.byteLength
            
            // second point
            guard bytes.count > ptr else {
                throw DataError.tooShort(bytes.count)
            }
            
            let secondPointMPint = try MPInt(mpintData: Data(bytes[ptr ..< bytes.count]))
            
            ptr += secondPointMPint.byteLength
            
            // pad points with 0s if needed
            let firstPoint = firstPointMPInt.data.padPrependedZeros(upto: 32)
            let secondPoint = secondPointMPint.data.padPrependedZeros(upto: 32)

            // concat points for raw signature data
            signature = [firstPoint, secondPoint]
        
        case .ecdsa:
            // first point
            let firstPointMPInt = try MPInt(mpintData: Data(bytes[ptr ..< bytes.count]))
            
            ptr += firstPointMPInt.byteLength
            
            // second point
            guard bytes.count > ptr else {
                throw DataError.tooShort(bytes.count)
            }
            
            let secondPointMPint = try MPInt(mpintData: Data(bytes[ptr ..< bytes.count]))
            
            ptr += secondPointMPint.byteLength
            
            // concat points for raw signature data
            signature = [firstPointMPInt.data, secondPointMPint.data]
            
        case .rsaEncryptOnly:
            throw PublicKeyAlgorithm.UnsupportedType(type: publicKeyAlgorithm.rawValue)
            
        }
        
        guard bytes.count == ptr else {
            throw ParsingError.signatureHasExtraBytes(bytes.count - ptr)
        }

    }
    
    // MARK: Signing Helpers
    public init(bare kind:Kind, publicKeyAlgorithm:PublicKeyAlgorithm, hashAlgorithm:HashAlgorithm, hashedSubpacketables:[SignatureSubpacketable] = []) {
        self.kind = kind
        self.publicKeyAlgorithm = publicKeyAlgorithm
        self.hashAlgorithm = hashAlgorithm
        self.hashedSubpacketables = hashedSubpacketables
        self.unhashedSubpacketables = []
        self.leftTwoHashBytes = []
        self.signature = []
    }
    
    /**
        Serialize the signature data that is part of the data to hash and sign
        https://tools.ietf.org/html/rfc4880#section-5.2.4
     */
    public func signedData() throws -> Data {
        var data = Data()
        
        data.append(contentsOf: [UInt8(supportedVersion)])
        data.append(contentsOf: [kind.rawValue])
        data.append(contentsOf: [publicKeyAlgorithm.rawValue])
        data.append(contentsOf: [hashAlgorithm.rawValue])
        
        // hashed subpackets
        let hashedSubpackets = try hashedSubpacketables.map({ try $0.toSubpacket() })
        let hashedSubpacketLength = hashedSubpackets.reduce(0, { $0 + $1.length })
        guard hashedSubpacketLength <= Int(UInt16.max) else {
            throw SerializingError.tooManySubpackets
        }
        // length
        data.append(contentsOf: UInt32(hashedSubpacketLength).twoByteBigEndianBytes())
        // data
        hashedSubpackets.forEach {
            data.append($0.toData())
        }
        
        return data
    }
    
    /**
        Serialize the signedData with the trailer that is to be hashed
        https://tools.ietf.org/html/rfc4880#section-5.2.4
     */
    public func dataToHash() throws -> Data {
        var dataToHash = Data()
        
        // append signature data
        let signatureData = try self.signedData()
        dataToHash.append(signatureData)
        
        // trailer
        dataToHash.append(self.trailer(for: signatureData))
        
        return dataToHash
    }

    /**
        Signature trailer
        https://tools.ietf.org/html/rfc4880#section-5.2.4
     */
    public func trailer(for signatureData:Data) -> Data {
        // trailer
        var data = Data()
        data.append(contentsOf: [UInt8(supportedVersion)])
        data.append(contentsOf: [0xFF])
        data.append(contentsOf: UInt32(signatureData.count).fourByteBigEndianBytes())
        
        return data
    }
    
    /**
        Set the signature data and left two hash bytes
     */
    mutating public func set(hash:Data, signedHash:[Data]) throws {
        guard hash.count >= 2 else {
            throw Signature.SerializingError.invalidHashLength(hash.count)
        }
        self.leftTwoHashBytes = [UInt8](hash.bytes[0...1])
        self.signature = signedHash
    }

    /**
        Serialize signature to packet body
     */
    public func toData() throws -> Data {
        var data = try signedData()
        
        // un-hashed subpackets
        let unhashedSubpackets = try unhashedSubpacketables.map({ try $0.toSubpacket() })
        let unhashedSubpacketLength = unhashedSubpackets.reduce(0, { $0 + $1.length })
        guard unhashedSubpacketLength <= Int(UInt16.max) else {
            throw SerializingError.tooManySubpackets
        }
        // length
        data.append(contentsOf: UInt32(unhashedSubpacketLength).twoByteBigEndianBytes())
        // data
        unhashedSubpackets.forEach {
            data.append($0.toData())
        }
        
        // left 16 bits
        data.append(contentsOf: leftTwoHashBytes)
        
        // signature MPI
        switch publicKeyAlgorithm {
        case .rsaEncryptOrSign, .rsaSignOnly, .ecdsa, .ed25519:
            for point in signature {
                let signatureMPInt = MPInt(integerData: point)
                
                data.append(contentsOf: signatureMPInt.lengthBytes)
                data.append(signatureMPInt.data)
            }
                        
        case .rsaEncryptOnly:
            throw PublicKeyAlgorithm.UnsupportedType(type: publicKeyAlgorithm.rawValue)
        }
        
        return data
    }

}


