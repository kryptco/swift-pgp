//
//  SignatureSubpacket.swift
//  PGPFormat
//
//  Created by Alex Grinman on 5/18/17.
//  Copyright © 2017 KryptCo, Inc. All rights reserved.
//

import Foundation

/**
    A Signature record type known as a "Signature Subpacket"
    https://tools.ietf.org/html/rfc4880#section-5.2.3.1
 */
public struct SignatureSubpacket {
    public let header:SignatureSubpacketHeader
    public let body:Data
    
    public var length:Int {
        return header.length + body.count
    }
    
    public func toData() -> Data {
        var data = Data()
        
        data.append(contentsOf: header.lengthBytes)
        data.append(contentsOf: [header.subpacketType.rawValue])
        data.append(contentsOf: body)
        
        return data
    }
}

/**
    Signature subpacket error types
 */
public enum SignatureSubpacketError:Error {
    case invalidLength(Int)
    case unsupportedType(UInt8)
}

/**
    A list of signature subpackets
 */
public extension Array where Element == SignatureSubpacket {
    
    init(data:Data) throws {
        
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


/**
    The header representing the body length of a Signature Subpacket
 */
public struct SignatureSubpacketHeader {
    public var subpacketType:SignatureSubpacketType
    
    private let typeLength = 1
    
    public let lengthLength:Int
    public let lengthBytes:[UInt8]
    public let bodyLength:Int
    
    public var length:Int {
        return typeLength + lengthLength
    }
    
    public func bodyRange() throws -> Range<Int> {
        let start   = typeLength + lengthLength
        let end     = start + bodyLength - typeLength
        
        guard start < end else {
            throw DataError.range(start, end)
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
    
    /**
        Initialize a subpacket header from a byte sequence
     */
    init(data:Data) throws {
        guard data.count > 0 else {
            throw DataError.tooShort(data.count)
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
            throw DataError.tooShort(bytes.count)
        }
        
        subpacketType = try SignatureSubpacketType(type: bytes[lengthLength + typeLength - 1])
    }
    
}

