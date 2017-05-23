//
//  AsciiArmor.swift
//  PGPFormat
//
//  Created by Alex Grinman on 5/15/17.
//  Copyright © 2017 KryptCo, Inc. All rights reserved.
//

import Foundation


/**
    Parse this format to pull out packet data.
     -----BEGIN PGP PUBLIC KEY BLOCK-----
     Comment: <String>
     <Base64 Data>
     =m4zw
     -----END PGP PUBLIC KEY BLOCK-----
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

public enum AsciiArmorError:Error {
    case noValidHeader
    case blockLineMismatch
    case missingChecksum
    case invalidChecksum
    case invalidArmor
    
}
public struct AsciiArmorMessage {
    
    public let packetData:Data
    public let crcChecksum:Data
    public let blockType:ArmorMessageBlock
    public var comment:String?
    
    public init(packets:[Packet], blockType:ArmorMessageBlock, comment:String? = "Created with swift-pgp") throws {
        var packetData = Data()
        try packets.forEach {
            try packetData.append($0.toData())
        }
        self.packetData = packetData
        self.crcChecksum = packetData.crc24Checksum
        self.blockType = blockType
        self.comment = comment
    }

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
    
    
    public func toString() -> String {
        let packetDataB64 = packetData.base64EncodedString(options: NSData.Base64EncodingOptions.lineLength64Characters)
        
        var result = ""
        
        result += "\(blockType.begin)\n"
        
        if let comment = self.comment {
            result += "\(ArmorMessageBlock.commentPrefix) \(comment)\n"
        }
        result += "\n"
        result += "\(packetDataB64)\n"
        result += "=\(crcChecksum.toBase64())\n"
        result += "\(blockType.end)\n"

        return result
    }
    
}
