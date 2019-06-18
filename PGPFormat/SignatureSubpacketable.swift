//
//  SignatureSubpacketable.swift
//  PGPFormat
//
//  Created by Alex Grinman on 6/4/17.
//  Copyright © 2017 KryptCo, Inc. All rights reserved.
//

import Foundation

/**
    Represents a structure that can be initialized
    from a SignatureSubpacket and converted to a SignatureSubpacket
 */
public protocol SignatureSubpacketable {
    var type:SignatureSubpacketType { get }
    init(packet:SignatureSubpacket) throws
    func toData() throws -> Data
}

public extension SignatureSubpacketable {
    func toSubpacket() throws -> SignatureSubpacket {
        let body = try self.toData()
        let header = try SignatureSubpacketHeader(type: self.type, bodyLength: body.count)
        
        return SignatureSubpacket(header: header, body: body)
    }
}

public enum SignatureSubpacketableError:Error {
    case invalidSubpacketType(SignatureSubpacketType)
}


/**
    Convert a list of signature subpackets to a list
    of signature subpacketables
 */
public extension Array where Element == SignatureSubpacket {
    func toSignatureSubpacketables() throws -> [SignatureSubpacketable] {
        var subpacketables = [SignatureSubpacketable]()
        
        for packet in self {
            switch packet.header.subpacketType {
            case .created:
                try subpacketables.append(SignatureCreated(packet: packet))
            case .keyExpires:
                try subpacketables.append(SignatureKeyExpires(packet: packet))
            case .issuer:
                try subpacketables.append(SignatureIssuer(packet: packet))
            case .keyFlags:
                try subpacketables.append(SignatureKeyFlags(packet: packet))
            case .issuerFingerprint:
                try subpacketables.append(SignatureIssuerFingerprint(packet: packet))
            default:
                try subpacketables.append(SignatureUnparsedSubpacket(packet: packet))
            }
        }
        
        return subpacketables
    }

}


