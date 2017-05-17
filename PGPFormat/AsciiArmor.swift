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
    case invalidArmor
}
public struct AsciiArmorMessage {
    
    public let packetData:Data
    public let crcChecksum:Data
    public let blockType:ArmorMessageBlock
    public var comment:String?
    
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
        
        if  lines[1].hasPrefix(ArmorMessageBlock.commentPrefix)
        {
            self.comment = lines[1].replacingOccurrences(of: ArmorMessageBlock.commentPrefix, with: "").trimmingCharacters(in: CharacterSet.whitespaces)
        }
        
        // crc
        self.crcChecksum = try lines[lines.count - 2].replacingOccurrences(of: "=", with: "").fromBase64()

        // footer
        let footerBlockType = ArmorMessageBlock(line: lines[lines.count - 1].trimmingCharacters(in: CharacterSet.whitespaces))
        
        guard headerBlockType == footerBlockType else {
            throw AsciiArmorError.blockLineMismatch
        }
        
        self.blockType = headerBlockType
        
        let packetsString = lines[2 ..< (lines.count - 2)].joined(separator: "")
        self.packetData = try packetsString.fromBase64()
    }
    
    public func toString() -> String {
        let packetDataB64 = packetData.base64EncodedString(options: NSData.Base64EncodingOptions.lineLength64Characters)
        
        return  "\(blockType.begin)\n"                                      +
                "\(ArmorMessageBlock.commentPrefix) \(comment ?? "\n")\n"   +
                "\n"                                                        +
                "\(packetDataB64)\n"                                        +
                "=\(crcChecksum.toBase64())\n"                              +
                "\(blockType.end)"
    }
    
}
