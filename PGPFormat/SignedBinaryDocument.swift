//
//  SignedBinaryDocument.swift
//  PGPFormat
//
//  Created by Alex Grinman on 5/21/17.
//  Copyright © 2017 KryptCo, Inc. All rights reserved.
//

import Foundation

/**
    Represents a signed binary document
    Packets: a signature packet
 */
public struct SignedBinaryDocument:Signable, Messagable {
    public var binaryData:Data
    
    public var signature:Signature
    public init(binary:Data, publicKeyAlgorithm:PublicKeyAlgorithm, hashAlgorithm:Signature.HashAlgorithm, hashedSubpacketables:[SignatureSubpacketable]) {
        
        binaryData = binary
        signature = Signature(bare: Signature.Kind.binaryDocument, publicKeyAlgorithm: publicKeyAlgorithm, hashAlgorithm: hashAlgorithm, hashedSubpacketables: hashedSubpacketables)
    }
    
    public func signableData() throws -> Data {
        return binaryData
    }
    
    public func toPackets() throws -> [Packet] {
        return try [self.signature.toPacket()]
    }
}
