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
    var pubkey2:String!
    var pubkeyEd25519:String!

    override func setUp() {
        super.setUp()
        
        let bundle = Bundle(for: type(of: self))
        pubkey1 = try! String(contentsOfFile: bundle.path(forResource: "pubkey1", ofType: "txt")!)
        pubkey2 = try! String(contentsOfFile: bundle.path(forResource: "pubkey2", ofType: "txt")!)
        pubkeyEd25519 = try! String(contentsOfFile: bundle.path(forResource: "pubkey3", ofType: "txt")!)

    }
    
    override func tearDown() {
        super.tearDown()
    }
    
    //MARK: Ascii Armor
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
    
    func testChecksum() {
        let data = try! "yDgBO22WxBHv7O8X7O/jygAEzol56iUKiXmV+XmpCtmpqQUKiQrFqclFqUDBovzSvBSFjNSiVHsuAA==".fromBase64()
        
        let check = data.crc24Checksum.toBase64()
        
        guard check == "njUN" else {
            XCTFail("mismatching checksum. got: \(check)")
            return
        }
    }
    
    //MARK: Packets
    
    func testPublicKeySerializeDeserializePacket() {
        do  {
            let pubMsg = try AsciiArmorMessage(string: pubkey1)
            let packets = try [Packet](data: pubMsg.packetData)
            
            for packet in [packets[0], packets[4]] {
                let packetOriginal = packet
                let pubKeyOriginal = try PublicKey(packet: packetOriginal)
                
                let packetSerialized = try pubKeyOriginal.toPacket()
                let pubKeyDeserialized = try PublicKey(packet: packetSerialized)
                
                guard packetSerialized.body == packetOriginal.body else {
                    print("original: \(packetOriginal.body.bytes)")
                    print("serialized: \(packetSerialized.body.bytes)")
                    XCTFail("packets differ after serialization deserialization")
                    return
                    
                }

            }
            
        } catch {
            XCTFail("Unexpected error: \(error)")

        }
    }
    
    func testPublicKeyTwoSerializeDeserializePacket() {
        do  {
            let pubMsg = try AsciiArmorMessage(string: pubkey2)
            let packets = try [Packet](data: pubMsg.packetData)
            
            for packet in [packets[0]] {                                
                let packetOriginal = packet
                let pubKeyOriginal = try PublicKey(packet: packetOriginal)
                
                let packetSerialized = try pubKeyOriginal.toPacket()
                let pubKeyDeserialized = try PublicKey(packet: packetSerialized)
                
                guard packetSerialized.body == packetOriginal.body else {
                    print("original: \(packetOriginal.body.bytes)")
                    print("serialized: \(packetSerialized.body.bytes)")
                    XCTFail("packets differ after serialization deserialization")
                    return
                    
                }
                
            }
            
        } catch {
            XCTFail("Unexpected error: \(error)")
            
        }
    }
    
    func testPublicKeyEd25519SerializeDeserializePacket() {
        do  {
            let pubMsg = try AsciiArmorMessage(string: pubkeyEd25519)
            let packets = try [Packet](data: pubMsg.packetData)
            
            let packetOriginal = packets[0]
            let pubKeyOriginal = try PublicKey(packet: packetOriginal)
            
            let packetSerialized = try pubKeyOriginal.toPacket()
            let pubKeyDeserialized = try PublicKey(packet: packetSerialized)
            
            guard packetSerialized.body == packetOriginal.body else {
                print("original: \(packetOriginal.body.bytes)")
                print("serialized: \(packetSerialized.body.bytes)")
                XCTFail("packets differ after serialization deserialization")
                return
                
            }
            
            let userID = try UserID(packet: packets[1])
            
            let signature = try Signature(packet: packets[2])
            
            let unknownData = try signature.hashedSubpacketables[0].toSubpacket().body
            let unknownBytes = unknownData.bytes
            print(unknownBytes)            
            print(String(data: unknownData, encoding: String.Encoding.utf8))
        } catch {
            XCTFail("Unexpected error: \(error)")
            
        }
    }


    
    func testFingerprintAndKeyId() {
        do  {
            let pubMsg = try AsciiArmorMessage(string: pubkey1)
            let packets = try [Packet](data: pubMsg.packetData)
            
            for packet in [packets[0]] {
                let packetOriginal = packet
                let pubKeyOriginal = try PublicKey(packet: packetOriginal)
                
                let fp = try pubKeyOriginal.fingerprint().hex
                let keyID = try pubKeyOriginal.keyID().hex
                
                guard fp.uppercased() == "F7A83D5CE65C42817A4AB7647A1037F5EF07891E" else {
                    XCTFail("Fingerprint does not match, got: \(fp)")
                    return
                }
                
                guard keyID.uppercased() == "7A1037F5EF07891E" else {
                    XCTFail("KeyID does not match, got: \(keyID)")
                    return
                }

            }
            
        } catch {
            XCTFail("Unexpected error: \(error)")
            
        }
    }

    
    // UserID
    func testUserIDPacket() {
        do  {
            let pubMsg = try AsciiArmorMessage(string: pubkey1)
            let packets = try [Packet](data: pubMsg.packetData)
            
            let packetOriginal = packets[1]
            let userIDOriginal = try UserID(packet: packetOriginal)
            
            let packetSerialized = try userIDOriginal.toPacket()
            let userIDDeserialized = try UserID(packet: packetSerialized)
            
            guard packetSerialized.body == packetOriginal.body else {
                print("original: \(packetOriginal.body.bytes)")
                print("serialized: \(packetSerialized.body.bytes)")
                XCTFail("packets differ after serialization deserialization")
                return
                
            }
            
        } catch {
            XCTFail("Unexpected error: \(error)")
            
        }
    }
    
    // Signature
    func testSignatureSerializeDeserializePacket() {
        do  {
            let pubMsg = try AsciiArmorMessage(string: pubkey1)
            let packets = try [Packet](data: pubMsg.packetData)
            
            for packet in [packets[2], packets[3], packets[5]] {
                let packetOriginal = packet
                let sigOriginal = try Signature(packet: packetOriginal)
                
                let packetSerialized = try sigOriginal.toPacket()
                let sigDeserialized = try Signature(packet: packetSerialized)
                
                guard packetSerialized.body == packetOriginal.body else {
                    print("original: \(packetOriginal.body.bytes)")
                    print("serialized: \(packetSerialized.body.bytes)")
                    XCTFail("packets differ after serialization deserialization")
                    return
                    
                }
            }
            
        } catch {
            XCTFail("Unexpected error: \(error)")
            
        }
    }
    
    // Test signature hash
    func testSignatureHashMatchesLeft16Bits() {
        do  {
            let pubMsg = try AsciiArmorMessage(string: pubkey1)
            let packets = try [Packet](data: pubMsg.packetData)
            
            let publicKey = try PublicKey(packet: packets[0])
            let userID = try UserID(packet: packets[1])
            let signature = try Signature(packet: packets[2])
            
            let created = (signature.hashedSubpacketables[0] as! SignatureCreated).date
            let pubKeyToSign = PublicKeyIdentityToSign(publicKey: publicKey, userID: userID, created: created)
            
            let dataToHash = try pubKeyToSign.dataToHash(hashAlgorithm: signature.hashAlgorithm)
            
            var hash:Data

            switch signature.hashAlgorithm {
            case .sha1:
                hash = dataToHash.SHA1
            case .sha224:
                hash = dataToHash.SHA224
            case .sha256:
                hash = dataToHash.SHA256
            case .sha384:
                hash = dataToHash.SHA384
            case .sha512:
                hash = dataToHash.SHA512
            }
            
            let leftTwoBytes = [UInt8](hash.bytes[0...1])
            
            guard leftTwoBytes == signature.leftTwoHashBytes else {
                XCTFail("Left two hash bytes don't match: \nGot: \(leftTwoBytes)\nExpected: \(signature.leftTwoHashBytes)")
                return
            }
            
            
        } catch {
            XCTFail("Unexpected error: \(error)")
            
        }
    }
    
    // Test output a simple public
    func testSimplePublicKeyOutput() {
        do  {
            let pubMsg = try AsciiArmorMessage(string: pubkey1)
            let packets = try [Packet](data: pubMsg.packetData)
            
            let publicKey = try PublicKey(packet: packets[0])
            let userID = try UserID(packet: packets[1])
            let signature = try Signature(packet: packets[3])
            
            let created = (signature.hashedSubpacketables[0] as! SignatureCreated).date
            let pubKeyToSign = PublicKeyIdentityToSign(publicKey: publicKey, userID: userID, created: created)
            
            let dataToHash = try pubKeyToSign.dataToHash(hashAlgorithm: signature.hashAlgorithm)
            
            var hash:Data

            switch signature.hashAlgorithm {
            case .sha1:
                hash = dataToHash.SHA1
            case .sha224:
                hash = dataToHash.SHA224
            case .sha256:
                hash = dataToHash.SHA256
            case .sha384:
                hash = dataToHash.SHA384
            case .sha512:
                hash = dataToHash.SHA512
            }
            
            let attributes = [SignatureSubpacketable](signature.hashedSubpacketables[1 ..< signature.hashedSubpacketables.count])
            
            attributes.forEach {
                print("-\($0.type):\n\t \($0)")
            }
            let signedPublicKey = try pubKeyToSign.signedPublicKey(hash: hash, hashAlgorithm: signature.hashAlgorithm, attributes: attributes, signatureData: signature.signature)
            
            let outPackets = try signedPublicKey.toPackets()
            let outMsg = try AsciiArmorMessage(packets: outPackets, blockType: ArmorMessageBlock.publicKey).toString()
            
            let inPackets = try [Packet](data: AsciiArmorMessage(string: outMsg).packetData)
            
            print(inPackets)
            
            print(outMsg)
        } catch {
            XCTFail("Unexpected error: \(error)")
            
        }
    }




}
