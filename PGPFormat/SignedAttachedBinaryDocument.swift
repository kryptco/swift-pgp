//
//  SignedAttachedBinaryDocument.swift
//  PGPFormat
//
//  Created by Alex Grinman on 6/20/17.
//  Copyright © 2017 KryptCo, Inc. All rights reserved.
//

import Foundation

/**
    Represents a signed binary document with the attached binary document as
    a literal data packet
    Packets: one pass signature packet, literal data packet, a signature packet
 */
public struct SignedAttachedBinaryDocument:Signable, Messagable {
    public var literalData:LiteralData
    public var keyID:Data
    public var signature:Signature
    
    public init(binaryData:Data, binaryDate:Date = Date(), keyID:Data, publicKeyAlgorithm:PublicKeyAlgorithm, hashAlgorithm:Signature.HashAlgorithm, hashedSubpacketables:[SignatureSubpacketable]) {
        
        self.literalData = LiteralData(contents: binaryData, formatType: .binary, date: binaryDate)
        self.keyID = keyID

        signature = Signature(bare: Signature.Kind.binaryDocument, publicKeyAlgorithm: publicKeyAlgorithm, hashAlgorithm: hashAlgorithm, hashedSubpacketables: hashedSubpacketables)
    }
    
    public func signableData() throws -> Data {
        return literalData.contents
    }
    
    public func toPackets() throws -> [Packet] {
        // create the one pass signature
        let onePass = OnePassSignature(signature: signature, keyID: keyID)
        
        // return one pass, literal data, and the signature packets
        return try [onePass.toPacket(), literalData.toPacket(), signature.toPacket()]
    }
}
