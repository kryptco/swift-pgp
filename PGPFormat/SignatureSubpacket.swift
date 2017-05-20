//
//  SignatureSubpacket.swift
//  PGPFormat
//
//  Created by Alex Grinman on 5/18/17.
//  Copyright © 2017 KryptCo, Inc. All rights reserved.
//

import Foundation




// MARK: SignatureSubpacketable

public protocol SignatureSubpacketable {
    var type:SignatureSubpacketType { get }
    init(packet:SignatureSubpacket) throws
    func toData() throws -> Data
}

public extension SignatureSubpacketable {

    public func toSubpacket() throws -> SignatureSubpacket {
        let body = try self.toData()
        let header = try SignatureSubpacketHeader(type: self.type, bodyLength: body.count)
        
        return SignatureSubpacket(header: header, body: body)
    }    
}

public enum SignatureSubpacketableError:Error {
    case invalidSubpacketType(SignatureSubpacketType)
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
    
    public func toSignatureSubpacketables() throws -> [SignatureSubpacketable] {
        var subpacketables = [SignatureSubpacketable]()
        
        for packet in self {
            switch packet.header.subpacketType {
            case .created:
                try subpacketables.append(SignatureCreated(packet: packet))
            case .keyExpires:
                try subpacketables.append(SignatureKeyExpires(packet: packet))
            case .issuer:
                try subpacketables.append(SignatureIssuer(packet: packet))
            case .keyFlags:
                try subpacketables.append(SignatureKeyFlags(packet: packet))
            case .issuerFingerprint:
                try subpacketables.append(SignatureIssuerFingerprint(packet: packet))
            default:
                try subpacketables.append(SignatureUnparsedSubpacket(packet: packet))
            }
        }
        
        return subpacketables
    }
}

public struct SignatureSubpacket {
    public let header:SignatureSubpacketHeader
    public let body:Data
    
    public var length:Int {
        return header.length + body.count
    }
    
    public func toData() throws -> Data {
        var data = Data()
        
        data.append(contentsOf: header.lengthBytes)
        data.append(contentsOf: [header.subpacketType.rawValue])
        data.append(contentsOf: body)
        
        return data
    }
}

public struct SignatureSubpacketHeader {
    public var subpacketType:SignatureSubpacketType
    
    private let typeLength = 1
    
    public var lengthLength:Int
    public var lengthBytes:[UInt8]
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
    
    init(type:SignatureSubpacketType, bodyLength:Int) throws {
        self.subpacketType = type
        self.bodyLength = bodyLength
        
        let realLength = bodyLength + typeLength
        
        switch realLength {
        case 0 ..< 192:
            self.lengthLength = 1
            self.lengthBytes = [UInt8(realLength)]
            
        case 192 ..< 8384:
            self.lengthLength = 2
            
            let firstByte = UInt8((UInt16(realLength - 192) >> 8) + 192)
            let secondByte = UInt8((realLength - 192) % Int(UInt8.max))
            self.lengthBytes = [firstByte, secondByte]
            
        case 8384 ..< Int(Int32.max):
            self.lengthLength = 5
            self.lengthBytes = [UInt8(255)] + UInt32(realLength).fourByteBigEndianBytes()
            
        default:
            throw SignatureSubpacketError.invalidLength(realLength)
        }


    }
    
    init(data:Data) throws {
        guard data.count > 0 else {
            throw FormatError.tooShort(data.count)
        }
        
        let bytes = data.bytes
        
        // read the length
        switch Int(bytes[0]) {
        case 0...191:
            lengthLength    = 1
            bodyLength      = Int(bytes[0])
            lengthBytes     = [bytes[0]]
            
        case 192 ..< 224 where bytes.count > 1:
            let firstOctet = Int(bytes[0])
            let secondOctet = Int(bytes[1])
            lengthBytes = [UInt8](bytes[0...1])

            lengthLength    = 2
            bodyLength      = ((firstOctet - 192) << 8) + secondOctet + 192
            
        case 255 where bytes.count > 4:
            let secondOctet = Int(bytes[1])
            let thirdOctet = Int(bytes[2])
            let fourthOctet = Int(bytes[3])
            let fifthOctet = Int(bytes[4])
            
            lengthLength    = 5
            bodyLength      = (secondOctet << 24) | (thirdOctet << 16) | (fourthOctet << 8)  | fifthOctet
            lengthBytes     = [UInt8](bytes[1...4])
            
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

/** 
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

public enum SignatureSubpacketError:Error {
    case invalidLength(Int)
    case unsupportedType(UInt8)
}
