//
//  AsciiArmor.swift
//  PGPFormat
//
//  Created by Alex Grinman on 5/15/17.
//  Copyright © 2017 KryptCo, Inc. All rights reserved.
//

import Foundation


/**
    ASCII Armor block constants
*/
public enum ArmorMessageBlock:String {
    case publicKey = "PUBLIC KEY BLOCK"
    case signature = "SIGNATURE"
    
    var begin:String {
        return "\(ArmorMessageBlock.begin)\(self.rawValue)\(ArmorMessageBlock.dashes)"
    }
    
    var end:String {
        return "\(ArmorMessageBlock.end)\(self.rawValue)\(ArmorMessageBlock.dashes)"
    }
    
    static let dashes   = "-----"
    static let begin    = "-----BEGIN PGP "
    static let end      = "-----END PGP "

    static var commentPrefix:String {
        return "Comment:"
    }
    
    
    init?(line:String) {
        let strippedHeader = line.replacingOccurrences(of: ArmorMessageBlock.begin, with: "").replacingOccurrences(of: ArmorMessageBlock.end, with: "").replacingOccurrences(of: ArmorMessageBlock.dashes, with: "")
        
        self.init(rawValue: strippedHeader)
    }
    
}

/**
    ASCII Armor Parsing Errors
*/
public enum AsciiArmorError:Error {
    case noValidHeader
    case blockLineMismatch
    case missingChecksum
    case invalidChecksum
    case invalidArmor
    
}

/**
    An ASCII Armored PGP Message.
    For example:
 
     -----BEGIN PGP PUBLIC KEY BLOCK-----
     Comment: <String>
     Data <String:Base64 Encoded Bytes>
     "=" + CRC24(Data) <String: Base64 encoded CRC-24 checksum>
     -----END PGP PUBLIC KEY BLOCK-----
 
    https://tools.ietf.org/html/rfc4880#section-6.2
 */
public struct AsciiArmorMessage {
    
    public let packetData:Data
    public let crcChecksum:Data
    public let blockType:ArmorMessageBlock
    public var comment:String?
    
    
    public init(packetData:Data, blockType:ArmorMessageBlock, comment:String?) {
        self.packetData = packetData
        self.crcChecksum = packetData.crc24Checksum
        self.blockType = blockType
        self.comment = comment
    }
    
    /**
        Convert a PGP Message to an ASCII Armored PGP Message block
     */
    public init(message:Message, blockType:ArmorMessageBlock, comment:String? = Constants.defaultASCIIArmorComment) throws {
        try self.init(packetData: message.data(), blockType: blockType, comment: comment)
    }

    /**
        Parse an ASCII Armor string
    */
    public init(string:String) throws {
        let lines = string.components(separatedBy: CharacterSet.newlines).filter { !$0.isEmpty }
        
        guard   lines.count > 0,
                let headerBlockType = ArmorMessageBlock(line: lines[0].trimmingCharacters(in: CharacterSet.whitespaces))
        else {
            throw AsciiArmorError.noValidHeader
        }
        
        guard lines.count > 3 else {
            throw AsciiArmorError.invalidArmor
        }
        
        var packetStart = 1
        if  lines[1].hasPrefix(ArmorMessageBlock.commentPrefix)
        {
            self.comment = lines[1].replacingOccurrences(of: ArmorMessageBlock.commentPrefix, with: "").trimmingCharacters(in: CharacterSet.whitespaces)
            packetStart += 1
        }
        
        // crc
        self.crcChecksum = try lines[lines.count - 2].replacingOccurrences(of: "=", with: "").fromBase64()

        // footer
        let footerBlockType = ArmorMessageBlock(line: lines[lines.count - 1].trimmingCharacters(in: CharacterSet.whitespaces))
        
        guard headerBlockType == footerBlockType else {
            throw AsciiArmorError.blockLineMismatch
        }
        
        self.blockType = headerBlockType
        
        let packets = try lines[packetStart ..< (lines.count - 2)].joined(separator: "").fromBase64()
        
        guard self.crcChecksum == packets.crc24Checksum else {
            throw AsciiArmorError.invalidChecksum
        }
        
        self.packetData = packets
    }
    
    /**
        Returns the ascii armored representation
    */
    public func toString() -> String {
        let packetDataB64 = packetData.base64EncodedString(options: [.lineLength64Characters, .endLineWithLineFeed])
        
        var result = ""
        
        result += "\(blockType.begin)\n"
        
        if let comment = self.comment {
            result += "\(ArmorMessageBlock.commentPrefix) \(comment)\n"
        }
        result += "\n"
        result += "\(packetDataB64)\n"
        result += "=\(crcChecksum.toBase64())\n"
        result += "\(blockType.end)"

        return result
    }
    
}
