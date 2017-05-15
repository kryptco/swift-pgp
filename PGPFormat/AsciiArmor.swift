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
    case publicKey = "PUBLIC KEY"
    case signature = "SIGNATURE"
    
    var begin:String {
        return " -----BEGIN PGP \(self.rawValue) BLOCK-----"
    }
    
    var end:String {
        return " -----END PGP \(self.rawValue) BLOCK-----"
    }

    static var commentPrefix:String {
        return "Comment:"
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
                let headerBlockType = ArmorMessageBlock(rawValue: lines[0].trimmingCharacters(in: CharacterSet.whitespaces))
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
        let footerBlockType = ArmorMessageBlock(rawValue: lines[lines.count - 1].trimmingCharacters(in: CharacterSet.whitespaces))
        
        guard headerBlockType == footerBlockType else {
            throw AsciiArmorError.blockLineMismatch
        }
        
        self.blockType = headerBlockType        
        self.packetData = try lines[2 ..< (lines.count - 1)].joined(separator: "").fromBase64()
    }
    
    public func toString() throws -> String {
        return  "\(self.blockType.begin)\n"         +
                "\(self.comment ?? "\n")\n"         +
                "\(self.packetData.toBase64())\n"   +
                "\(self.crcChecksum.toBase64())\n"  +
                "\(self.blockType.end)\n"
    }
    
}
