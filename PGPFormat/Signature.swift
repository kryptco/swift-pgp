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
public struct Signature {
    
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

    public init(data:Data) throws {
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
        
        /**
         
             - One or more multiprecision integers comprising the signature.
             This portion is algorithm specific, as described above.
         */
        
        
        // hashed subpackets
        let hashedDataLength = Int(Int32(bigEndianBytes: [UInt8](bytes[4 ... 5])))
        
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
        
        let unhashedDataLength = Int(Int32(bigEndianBytes: [UInt8](bytes[ptr ... ptr + 1])))
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
            
            let signatureLength = Int(Int32(bigEndianBytes: [UInt8](bytes[ptr ... ptr + 1])))/8
            ptr += 2
            
            guard bytes.count >= ptr + signatureLength else {
                throw FormatError.tooShort(bytes.count)
            }
            
            signature = Data(bytes: bytes[ptr ..< (ptr + signatureLength)])

        default:
            throw UnsupportedPublicKeyAlgorithm(type: publicKeyAlgorithm.rawValue)
            
        }

    }

}


/**
    Signature Subpacket(s)
    https://tools.ietf.org/html/rfc4880#section-5.2.3.1
 */

public extension Array where Element == SignatureSubpacket {
    
    public init(data:Data) throws {
        
        var packetStart = 0
        
        var packets:[SignatureSubpacket] = []
        
        while packetStart < data.count {
            let nextData = Data(data.suffix(from: packetStart))
            
            let header = try SignatureSubpacketHeader(data: nextData)            
            let body = try nextData.safeSubdata(in: header.bodyRange())
            let packet = SignatureSubpacket(header: header, body: body)
            
            packets.append(packet)

            packetStart += packet.length
        }
        
        self = packets
    }
}

public struct SignatureSubpacket {
    public let header:SignatureSubpacketHeader
    public let body:Data
    
    public var length:Int {
        return header.length + body.count
    }
}

public struct SignatureSubpacketHeader {
    public var subpacketType:SignatureSubpacketType
    
    private let typeLength = 1

    public var lengthLength:Int
    public var bodyLength:Int

    public var length:Int {
        return typeLength + lengthLength
    }
    
    public func bodyRange() throws -> Range<Int> {
        let start   = typeLength + lengthLength
        let end     = start + bodyLength - typeLength
        
        guard start < end else {
            throw FormatError.badRange(start, end)
        }
        
        return start ..< end
    }

    
    init(data:Data) throws {
        guard data.count > 0 else {
            throw FormatError.tooShort(data.count)
        }
        
        let bytes = data.bytes
                
        // read the length
        switch Int(bytes[0]) {
        case 0...191:
            lengthLength = 1
            bodyLength = Int(bytes[0])
            
        case 192 ..< 255 where bytes.count > 1:
            let firstOctet = Int(bytes[0])
            let secondOctet = Int(bytes[1])
            
            lengthLength = 2
            bodyLength = ((firstOctet - 192) << 8) + secondOctet + 192
        
        case 255 where bytes.count > 4:
            let secondOctet = Int(bytes[1])
            let thirdOctet = Int(bytes[2])
            let fourthOctet = Int(bytes[3])
            let fifthOctet = Int(bytes[4])
            
            lengthLength = 5
            bodyLength = (secondOctet << 24) | (thirdOctet << 16) | (fourthOctet << 8)  | fifthOctet
        
        default:
            throw SignatureSubpacketError.invalidLength(bytes.count)
        }
        
        // read the type
        guard bytes.count >= lengthLength + typeLength else {
            throw FormatError.tooShort(bytes.count)
        }
        
        subpacketType = try SignatureSubpacketType(type: bytes[lengthLength + typeLength - 1])
    }

}

public enum SignatureSubpacketType:UInt8 {
    case created        = 2
    case sigExpires     = 3
    case trust          = 5
    case keyExpires     = 9
    case issuer         = 16
    case primaryUserID  = 25
    
    init(type:UInt8) throws {
        guard let sigType = SignatureSubpacketType(rawValue: type) else {
            throw SignatureSubpacketError.unsupportedType(type)
        }
        
        self = sigType
    }

}

public enum SignatureSubpacketError:Error {
    case invalidLength(Int)
    case unsupportedType(UInt8)
}

