//
//  PGPFormatTests.swift
//  PGPFormatTests
//
//  Created by Alex Grinman on 5/17/17.
//  Copyright © 2017 KryptCo, Inc. All rights reserved.
//

import XCTest
@testable import PGPFormat

class PGPFormatTests: XCTestCase {
    
    var pubkey1:String!
    override func setUp() {
        super.setUp()
        
        let bundle = Bundle(for: type(of: self))
        let path = bundle.path(forResource: "pubkey1", ofType: "txt")!
        pubkey1 = try! String(contentsOfFile: path)
    }
    
    override func tearDown() {
        super.tearDown()
    }
    
    func testAsciiArmor() {
        do {
            let pubMsg = try AsciiArmorMessage(string: pubkey1)

            if pubMsg.comment != "Some test hello" {
                XCTFail("invalid comment: \(pubMsg.comment)")
            }
            
            if pubMsg.crcChecksum.toBase64() != "m4zw" {
                XCTFail("invalid checksum: \(pubMsg.crcChecksum.toBase64())")
            }
            
            if pubMsg.blockType != ArmorMessageBlock.publicKey {
                XCTFail("invalid block type: \(pubMsg.blockType)")
            }
            
            let pubMsgAgain = try AsciiArmorMessage(string: pubMsg.toString())

        } catch {
            XCTFail("Unexpected error: \(error)")
        }
    }
    
}
