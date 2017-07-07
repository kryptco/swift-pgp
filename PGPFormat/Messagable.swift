//
//  Messagable.swift
//  PGPFormat
//
//  Created by Alex Grinman on 6/3/17.
//  Copyright © 2017 KryptCo, Inc. All rights reserved.
//

import Foundation

/**
    Represents something that can be made into a PGP Message.
*/
public protocol Messagable {
    func toPackets() throws -> [Packet]
}

extension Messagable {
    public func toMessage() throws -> Message {
        return try Message(packets: self.toPackets())
    }
}
