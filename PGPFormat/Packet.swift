//
//  Packet.swift
//  PGPFormat
//
//  Created by Alex Grinman on 5/15/17.
//  Copyright © 2017 KryptCo, Inc. All rights reserved.
//



import Foundation

//MARK: Packet(s)

public extension Array where Element == Packet {
    
    public init(data:Data) throws {
        
        var packetStart = 0
        var packets:[Packet] = []
        
        while packetStart < data.count {
            let nextData = Data(data.suffix(from: packetStart))
            
            let header = try PacketHeader(data: nextData)
            let body = try nextData.subdata(in: header.bodyRange())
            
            let packet = Packet(header: header, body: body)
            packets.append(packet)
            
            packetStart += packet.length
        }
        
        self = packets
    }
}

public struct Packet {
    public let header:PacketHeader
    public let body:Data
    
    public var length:Int {
        return header.length + body.count
    }
}

// MARK: Packetable

public protocol PacketReadable {
    init(data:Data) throws
}

public protocol PacketWritable {
    func toPacket() throws -> Data
}

public protocol Packetable: PacketReadable, PacketWritable {}

// MARK: Errors
public enum FormatError:Error {
    case tooShort(Int)
    case badRange(Int,Int)
    case encoding

}

public enum PacketError:Error {
    case msbUnset
    case unsupportedTagType(UInt8)
    
    case unsupportedNewFormatLengthType(UInt8)
    case unsupportedOldFormatLengthType(UInt8)

    case partial(UInt8)
}




/**
    First octet: Pack Tag
     +---------------+
     PTag |7 6 5 4 3 2 1 0|
     +---------------+
 
    - Bit 7 -- Always one
    - Bit 6 -- New packet format if set
 
    - NewFormat:
         Bits 5-0 -- packet tag
 
    - OldFormat:
         Bits 5-2 -- packet tag
         Bits 1-0 -- length-type

 */
public struct PacketHeader {

    public var tag:PacketTag
    
    private let tagLength = 1
    public var lengthLength:Int
    public var bodyLength:Int

    public var length:Int {
        return tagLength + lengthLength
    }
    
    public func bodyRange() throws -> Range<Int> {
        let start   = tagLength + lengthLength
        let end     = start + bodyLength
        
        guard start < end else {
            throw FormatError.badRange(start, end)
        }
        
        return start ..< end
    }
    
    public init(data:Data) throws {
        guard data.count > 0 else {
            throw FormatError.tooShort(data.count)
        }
        
        let bytes = data.bytes
        
        // parse packet tag
        let firstOctet = bytes[0]

        guard (firstOctet & 0b10000000) >> 7 == 1 else {
            throw PacketError.msbUnset
        }

        let newFormat = ((firstOctet & 0b01000000) >> 6) == 1
        
        if newFormat {            
            let packetLength = try PacketLength(newFormat: [UInt8](bytes.suffix(from: 1)))
            
            tag = try PacketTag(tag: firstOctet & 0b00111111)
            lengthLength = packetLength.length
            bodyLength = packetLength.value
        } else {
            let lengthType = firstOctet & 0b00000011
            let packetLength = try PacketLength(oldFormat: [UInt8](bytes.suffix(from: 1)), type: lengthType)
            
            tag = try PacketTag(tag: (firstOctet & 0b00111100)>>2)
            lengthLength = packetLength.length
            bodyLength = packetLength.value
        }
    }
}

struct PacketLength {
    
    var length:Int
    var value:Int
    
    /**
        New Format Parsing
    */
    init(newFormat bytes:[UInt8]) throws {
        guard bytes.count > 0 else {
            throw FormatError.tooShort(bytes.count)
        }
        
        switch Int(bytes[0]) {
        case 0...191: // one octet
            length = 1
            value = Int(bytes[0])
            
        case 192 ..< 224 where bytes.count > 1: // two octet
            let firstOctet = Int(bytes[0])
            let secondOctet = Int(bytes[1])
            
            length = 2
            value = ((firstOctet - 192) << 8) + secondOctet + 192
            
        case 255 where bytes.count > 4: // five octet
            let secondOctet = Int(bytes[1])
            let thirdOctet = Int(bytes[2])
            let fourthOctet = Int(bytes[3])
            let fifthOctet = Int(bytes[4])
            
            length = 5
            value = (secondOctet << 24) | (thirdOctet << 16) | (fourthOctet << 8)  | fifthOctet
            
        default:
            throw PacketError.unsupportedNewFormatLengthType(bytes[0])
        }
    }
    
    
    /**
        Old Format Parsing
        https://tools.ietf.org/html/rfc4880 section 4.2.1
     */
    enum OldFormatType:UInt8 {
        case oneOctet = 0
        case twoOctet = 1
        case fourOctet = 2
    }
    init(oldFormat bytes:[UInt8], type:UInt8) throws {
        guard let lengthType = OldFormatType(rawValue: type) else {
            throw PacketError.unsupportedOldFormatLengthType(type)
        }
        
        switch lengthType {
        case .oneOctet where bytes.count > 0:
            length = 1
            value = Int(bytes[0])

        case .twoOctet where bytes.count > 1:
            let firstOctet = Int(bytes[0])
            let secondOctet = Int(bytes[1])
            
            length = 2
            value = (firstOctet << 8) | secondOctet

        case .fourOctet where bytes.count > 4:
            let firstOctet = Int(bytes[0])
            let secondOctet = Int(bytes[1])
            let thirdOctet = Int(bytes[2])
            let fourthOctet = Int(bytes[3])

            length = 4
            value = (firstOctet << 24) | (secondOctet << 16) | (thirdOctet << 8)  | fourthOctet
            
        default:
            throw FormatError.tooShort(bytes.count)
        }
        
    }

}


/**
 0        -- Reserved - a packet tag MUST NOT have this value
 1        -- Public-Key Encrypted Session Key Packet
 2        -- Signature Packet
 3        -- Symmetric-Key Encrypted Session Key Packet
 4        -- One-Pass Signature Packet
 5        -- Secret-Key Packet
 6        -- Public-Key Packet
 7        -- Secret-Subkey Packet
 8        -- Compressed Data Packet
 9        -- Symmetrically Encrypted Data Packet
 10       -- Marker Packet
 11       -- Literal Data Packet
 12       -- Trust Packet
 13       -- User ID Packet
 14       -- Public-Subkey Packet
 17       -- User Attribute Packet
 18       -- Sym. Encrypted and Integrity Protected Data Packet
 19       -- Modification Detection Code Packet
 60 to 63 -- Private or Experimental Values
 */
public enum PacketTag:UInt8 {
    case signature      = 2
    case secretKey      = 5
    case publicKey      = 6
    case marker         = 10
    case literalData    = 11
    case trust          = 12
    case userID         = 13
    case publicSubkey   = 14
    case userAttribute  = 17
    
    init(tag:UInt8) throws {
        guard let packetTag = PacketTag(rawValue: tag) else {
            throw PacketError.unsupportedTagType(tag)
        }
        self = packetTag
    }
}


