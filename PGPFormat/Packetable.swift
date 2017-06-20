//
//  Packetable.swift
//  PGPFormat
//
//  Created by Alex Grinman on 6/3/17.
//  Copyright © 2017 KryptCo, Inc. All rights reserved.
//

import Foundation

/**
    Represents a structure that can be initialized
    from a packet and converted to a packet
 */
public protocol Packetable {
    /**
        Retreive the packet tag identiifer
     */
    var tag:PacketTag { get }
    
    /**
        Create a Packetable from a packet
     */
    init(packet:Packet) throws
    
    /**
        Convert a packetable to a byte sequence
     */
    func toData() throws -> Data
}

public extension Packetable {
    
    /**
        Convert a packetable to a packet
     */
    public func toPacket() throws -> Packet {
        let body = try self.toData()
        let header = try PacketHeader(tag: self.tag, packetLength: PacketLength(body: body.count))
        
        return Packet(header: header, body: body)
    }
}

/**
    Packetable initialization errors
 */
public enum PacketableError:Error {
    case invalidPacketTag(PacketTag)
}

/**
    Initialize a list of packetables from a byte sequence
 */
public extension Array where Element == Packetable {
    public init(data:Data) throws {
        let packets = try [Packet](data: data)
        
        self = try packets.map {
            switch $0.header.tag {
            case .publicKey, .publicSubkey:
                return try PublicKey(packet: $0)
            case .userID:
                return try UserID(packet: $0)
            case .signature:
                return try Signature(packet: $0)
            case .onePassSignature:
                return try OnePassSignature(packet: $0)
            case .literalData:
                return try LiteralData(packet: $0)
            }
        }
    }
}

/**
 for testing purposes
public struct BasePacket:Packetable {
    public var tag:PacketTag
    var bodyData:Data
    
    public init(packet:Packet) throws {
        tag = packet.header.tag
        bodyData = packet.body
    }
    
    public func toData() throws -> Data {
        return bodyData
    }
}
*/



