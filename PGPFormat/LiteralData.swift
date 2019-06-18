//
//  LiteralData.swift
//  PGPFormat
//
//  Created by Alex Grinman on 6/20/17.
//  Copyright © 2017 KryptCo, Inc. All rights reserved.
//

import Foundation

/**
    A Literal Data packet
    https://tools.ietf.org/html/rfc4880#section-5.9
 */
public struct LiteralData:Packetable {
    
    public var tag:PacketTag {
        return .literalData
    }
    
    public enum ParsingError:Error {
        case unsupportedFormatType(UInt8)
    }
    
    public enum SerializingError:Error {
        case filenameTooLong(Int)
    }

    
    public enum FormatType:UInt8 {
        case binary     = 0x62
        case text       = 0x74
        case utf8Text   = 0x75
        
        init(type:UInt8) throws {
            guard let formatType = FormatType(rawValue: type) else {
                throw ParsingError.unsupportedFormatType(type)
            }
            self = formatType
        }
    }
    
    public var formatType:FormatType
    public var filename:Data
    public var date:Date
    public var contents:Data
    
    public init(packet:Packet) throws {
        guard packet.header.tag == .literalData else {
            throw PacketableError.invalidPacketTag(packet.header.tag)
        }
        
        // parse the body
        let data = packet.body
        
        guard data.count >= 5 else {
            throw DataError.tooShort(data.count)
        }
        
        let bytes = data.bytes
        
        // format
        formatType  = try FormatType(type: bytes[0])
        
        // filename (1 byte length, then string)
        let filenameLength = Int(bytes[1])
        
        var ptr = 2
        guard data.count >= ptr + filenameLength else {
            throw DataError.tooShort(data.count)

        }
        filename = Data(bytes[ptr ..< (ptr + filenameLength)])
        ptr += filenameLength
        
        // date (1 ..< 5)
        guard data.count >= ptr + 4 else {
            throw DataError.tooShort(data.count)
        }
        
        let creationSeconds = Double(UInt32(bigEndianBytes: [UInt8](bytes[ptr ..< (ptr + 4)])))
        date = Date(timeIntervalSince1970: creationSeconds)
        ptr += 4
        
        // contents, remainder
        guard data.count >= ptr+1 else {
            throw DataError.tooShort(data.count)
        }

        contents = Data([UInt8](bytes.suffix(from: ptr)))
    }
    
    init(contents:Data, formatType:FormatType = .binary, filename:Data = Data(), date:Date = Date()) {
        self.contents = contents
        self.formatType = formatType
        self.filename = filename
        self.date = date
    }
    
    public func toData() throws -> Data {
        var data = Data()
        
        // format byte
        data.append(contentsOf: [formatType.rawValue])
        
        // filename length 1 byte, plus contents
        guard filename.count < Int(UInt8.max) else {
            throw SerializingError.filenameTooLong(filename.count)
        }
        data.append(UInt8(filename.count))
        data.append(filename)

        // date
        data.append(contentsOf: UInt32(date.timeIntervalSince1970).fourByteBigEndianBytes())
        
        // literal data
        data.append(contents)
        
        return data
    }
}



