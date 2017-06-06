//
//  Packet.swift
//  PGPFormat
//
//  Created by Alex Grinman on 5/15/17.
//  Copyright © 2017 KryptCo, Inc. All rights reserved.
//

import Foundation


/**
    A PGP data record.
    https://tools.ietf.org/html/rfc4880#section-4
*/
public struct Packet {
    public let header:PacketHeader
    public let body:Data

    public var length:Int {
        return header.realLength + body.count
    }
    
    public func toData() -> Data {
        var data = Data()
        
        data.append(contentsOf: header.bytes())
        data.append(contentsOf: body)

        return data
    }
}

/**
    A list of PGP data records.
 */
public extension Array where Element == Packet {
    
    /** 
        Initialize a list of packets from a byte sequence
     */
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

/**
    Packet creation/serialization errors
 */
public enum PacketError:Error {
    case msbUnset
    case unsupportedTagType(UInt8)
    
    case unsupportedNewFormatLengthType(UInt8)
    case unsupportedOldFormatLengthType(UInt8)

    case partial(UInt8)
    
    case bodyLengthTooLong(Int)
    case invalidPacketLengthFormatByteLength(Int)
}


/**
    A header for the packet to determine the packet tag 
    identifier and body length
 
    First octet of the packet header:
     +---------------+
     PTag |7 6 5 4 3 2 1 0|
     +---------------+
 
    Bits 7-6:
        - Bit 7 -- Always one
        - Bit 6 -- New packet format if set
 
    Bits 5-0:
        - NewFormat:
            Bits 5-0 -- packet tag
        - OldFormat:
            Bits 5-2 -- packet tag
            Bits 1-0 -- length-type
    
    https://tools.ietf.org/html/rfc4880#section-4.2
 */
public struct PacketHeader {

    public let tag:PacketTag
    public let length:PacketLength

    private let tagLength = 1

    public var realLength:Int {
        return tagLength + length.byteLength()
    }
    
    /**
        Data range for packet body
     */
    public func bodyRange() throws -> Range<Int> {
        let start   = realLength
        let end     = start + length.body
        
        guard start < end else {
            throw DataError.range(start, end)
        }
        
        return start ..< end
    }
    
    init(tag:PacketTag, packetLength:PacketLength) {
        self.length = packetLength
        self.tag = tag
    }
    
    /**
        Initialize packet header from byte sequence
     */
    public init(data:Data) throws {
        guard data.count > 0 else {
            throw DataError.tooShort(data.count)
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
            let packetTag = try PacketTag(tag: firstOctet & 0b00111111)
            self.init(tag: packetTag, packetLength: packetLength)
            
        } else {
            let lengthType = firstOctet & 0b00000011
            let packetLength = try PacketLength(oldFormat: [UInt8](bytes.suffix(from: 1)), type: lengthType)
            let packetTag = try PacketTag(tag: (firstOctet & 0b00111100)>>2)
            
            self.init(tag: packetTag, packetLength: packetLength)
        }
    }
    
    /**
        Compute the first byte, the tag byte, of the packet header
     */
    func tagByte() -> UInt8 {
        let msb:UInt8 = 0b10000000
        let format:UInt8 = length.isNewFormat() ? 0b01000000 : 0b00000000
        
        var tagBits:UInt8
        var lengthType:UInt8

        switch length.length {
        case .new(_):
            tagBits = tag.rawValue
            lengthType = 0b00000000
        case .old(let l):
            tagBits = tag.rawValue << 2
            lengthType = l.rawValue
        }

        return msb | format | tagBits | lengthType
    }
    
    /**
        Convert the packet header to a byte sequence
     */
    func bytes() -> Data {
        var data = Data()
        
        data.append(contentsOf: [tagByte()])
        data.append(contentsOf: length.formatBytes)

        return data
    }

}

/**
    Represents the type of packet (the packet tag)
    https://tools.ietf.org/html/rfc4880#section-4.3
 
    //NOTE: not all currently supported
 */
public enum PacketTag:UInt8 {
    case signature      = 2
    case publicKey      = 6
    case userID         = 13
    case publicSubkey   = 14
    
    init(tag:UInt8) throws {
        guard let packetTag = PacketTag(rawValue: tag) else {
            throw PacketError.unsupportedTagType(tag)
        }
        self = packetTag
    }
}


/**
    Represents the length of the packet body
 */
public struct PacketLength {

    let length:Length
    let body:Int
    
    let formatBytes:[UInt8]
    
    /**
        Create a packet length from the length of a packet body
        //TODO: add support new format
     */
    public init(body:Int) throws {
        self.body = body
        
        switch body {
        case 0 ..< Int(UInt8.max):
            length = .old(.oneOctet)
            formatBytes = [UInt8(body)]

        case 256 ..< Int(UInt16.max):
            length = .old(.twoOctet)
            formatBytes = UInt32(body).twoByteBigEndianBytes()
            
        case Int(UInt16.max) ..< Int(Int32.max):
            length = .old(.fourOctet)
            formatBytes = UInt32(body).fourByteBigEndianBytes()
        
        default:
            throw PacketError.bodyLengthTooLong(body)
        }
    }
    
    /**
        Initialize a packet length with from a 'New Format' packet header
        https://tools.ietf.org/html/rfc4880#section-4.2.2
    */
    init(newFormat bytes:[UInt8]) throws {
        guard bytes.count > 0 else {
            throw DataError.tooShort(bytes.count)
        }
        
        switch Int(bytes[0]) {
        case 0...191: // one octet
            length = .new(.oneOctet)
            body = Int(bytes[0])
            formatBytes = [bytes[0]]
            
        case 192 ..< 224 where bytes.count >= 2: // two octet
            let firstOctet = Int(bytes[0])
            let secondOctet = Int(bytes[1])
            
            length = .new(.twoOctet)
            body = ((firstOctet - 192) << 8) + secondOctet + 192
            formatBytes = [UInt8](bytes[0...1])
            
        case 255 where bytes.count >= 5: // five octet
            let secondOctet = Int(bytes[1])
            let thirdOctet = Int(bytes[2])
            let fourthOctet = Int(bytes[3])
            let fifthOctet = Int(bytes[4])
            
            length = .new(.fiveOctet)
            body = (secondOctet << 24) | (thirdOctet << 16) | (fourthOctet << 8)  | fifthOctet
            formatBytes = [UInt8](bytes[1...4])

        default:
            throw PacketError.unsupportedNewFormatLengthType(bytes[0])
        }
    }
    
    
    /**
        Initialize a packet length with from a 'Old Format' packet header
        https://tools.ietf.org/html/rfc4880#section-4.2.1
     */
    init(oldFormat bytes:[UInt8], type:UInt8) throws {
        guard let lengthType = OldFormatType(rawValue: type) else {
            throw PacketError.unsupportedOldFormatLengthType(type)
        }
        
        switch lengthType {
        case .oneOctet where bytes.count >= 1:
            length = .old(.oneOctet)
            body = Int(bytes[0])
            formatBytes = [bytes[0]]


        case .twoOctet where bytes.count >= 2:
            let firstOctet = Int(bytes[0])
            let secondOctet = Int(bytes[1])
            
            length = .old(.twoOctet)
            body = (firstOctet << 8) | secondOctet
            formatBytes = [UInt8](bytes[0...1])


        case .fourOctet where bytes.count >= 4:
            let firstOctet = Int(bytes[0])
            let secondOctet = Int(bytes[1])
            let thirdOctet = Int(bytes[2])
            let fourthOctet = Int(bytes[3])

            length = .old(.fourOctet)
            body = (firstOctet << 24) | (secondOctet << 16) | (thirdOctet << 8)  | fourthOctet
            formatBytes = [UInt8](bytes[0...3])
            
        default:
            throw DataError.tooShort(bytes.count)
        }
    }

    enum OldFormatType:UInt8 {
        case oneOctet = 0
        case twoOctet = 1
        case fourOctet = 2
    }

    enum NewFormatType {
        case oneOctet
        case twoOctet
        case fiveOctet
    }

    enum Length {
        case new(NewFormatType)
        case old(OldFormatType)

        func byteLength() -> UInt8 {
            switch self {
            case .old(let l):
                switch l {
                case .oneOctet:
                    return 1
                case .twoOctet:
                    return 2
                case .fourOctet:
                    return 4
                }
            case .new(let l):
                switch l {
                case .oneOctet:
                    return 1
                case .twoOctet:
                    return 2
                case .fiveOctet:
                    return 5
                }
            }
        }
    }
    
    func byteLength() ->  Int {
        return Int(length.byteLength())
    }

    func isNewFormat() -> Bool {
        switch length {
        case .old(_):
            return false
        case .new(_):
            return true
        }
    }
    
}


