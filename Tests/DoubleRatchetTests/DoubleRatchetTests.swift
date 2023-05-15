//
//  Copyright © 2019 Anbion. All rights reserved.
//

import XCTest
import Sodium
@testable import DoubleRatchet

/// this extension exists here for the purpose of making these XCTests functional and passing
/// as they were written from the original "forked" repo
extension DoubleRatchet {
    public convenience init(keyPair: KeyPair?, remotePublicKey: PublicKey?, sharedSecret: Bytes, maxSkip: Int, maxCache: UInt, info: String) throws {
        MessageKeyCacheInMemoryTest.shared.maxCacheEntries = maxCache
        try self.init(keyPair: keyPair, remotePublicKey: remotePublicKey, sharedSecret: sharedSecret, maxSkip: maxSkip, info: info, messageKeyCache: MessageKeyCacheInMemoryTest.shared)
    }
    public convenience init(sessionState: SessionState) {
        self.init(sessionState: sessionState,messageKeyCache: MessageKeyCacheInMemoryTest.shared)
    }
}

/// this is a very ineffient approach to a memory cache
/// and should not be used as a "real" implementation
/// however it is relatively easy to follow and should work for
/// unit and integration tests
class MessageKeyCacheInMemoryTest : MessageKeyCache {
    
    public var rootKeyPair: KeyPair? = nil
    var pubKeyMsgNumDict: [PublicKey:[Int:MsgKeyItem]] = [:]
    private static var messageKeyCacheInMemoryTest:MessageKeyCacheInMemoryTest?
    /// must be a number larger than 0, if set to 0, it will be UInt.max
    public var maxCacheEntries = UInt.max {
        didSet {
            if maxCacheEntries == 0 {
                maxCacheEntries = UInt.max
            }
        }
    }
    private var numCacheEntries:UInt = 0

    struct MsgKeyItem: Codable {
        let messageKey: MessageKey
        let date: Date
    }
    
    static var shared: MessageKeyCacheInMemoryTest {
        if messageKeyCacheInMemoryTest == nil {
            messageKeyCacheInMemoryTest = MessageKeyCacheInMemoryTest()
        }
        return messageKeyCacheInMemoryTest!
    }
    
    func add(messageKey: MessageKey, messageNumber: Int, publicKey: PublicKey) throws {
        guard (try? getMessageKey(messageNumber: messageNumber, publicKey: publicKey)) == nil else {
            return
        }
        while numCacheEntries >= maxCacheEntries {
            try dropOldestEntry()
        }
        let messageKeyItem = MsgKeyItem(messageKey: messageKey, date: Date.now)
        if pubKeyMsgNumDict[publicKey] != nil {
            pubKeyMsgNumDict[publicKey]?[messageNumber] = messageKeyItem
        } else {
            pubKeyMsgNumDict[publicKey] = [messageNumber:messageKeyItem]
        }
        numCacheEntries += 1
    }
    
    func getMessageKey(messageNumber: Int, publicKey: PublicKey) throws -> MessageKey? {
        let msgNumToMsgKey = pubKeyMsgNumDict[publicKey]
        let msgKeyItem = msgNumToMsgKey?[messageNumber]
        return msgKeyItem?.messageKey
    }
    
    func remove(publicKey: PublicKey, messageNumber: Int) throws {
        pubKeyMsgNumDict[publicKey]?.removeValue(forKey: messageNumber)
        if pubKeyMsgNumDict[publicKey]?.count == 0 {
            pubKeyMsgNumDict.removeValue(forKey: publicKey)
        }
        numCacheEntries -= 1
    }
    
    private func dropOldestEntry() throws {
        var oldestPubKey: PublicKey?
        var oldestMsgNum: Int?
        var oldestDate: Date?
        for (pkey, value) in pubKeyMsgNumDict {
            for (mNum, msgKI) in value {
                if (oldestDate == nil || msgKI.date < oldestDate!) {
                    oldestDate = msgKI.date
                    oldestPubKey = pkey
                    oldestMsgNum = mNum
                }
            }
        }
        if let oldestPubKey = oldestPubKey, let oldestMsgNum = oldestMsgNum {
            try remove(publicKey: oldestPubKey, messageNumber: oldestMsgNum)
        }
    }

}

final class DoubleRatchetTests: XCTestCase {

    let sodium = Sodium()
    let sharedSecret = Sodium().utils.hex2bin("00 11 22 33 44 55 66 77 88 99 AA BB CC DD EE FF 00 11 22 33 44 55 66 77 88 99 AA BB CC DD EE FF", ignore: " ")!

    var alice: DoubleRatchet!
    var bob: DoubleRatchet!
    let info = "DoubleRatchetTest"

    override func setUp() {
        super.setUp()

        bob = try! DoubleRatchet(keyPair: nil, remotePublicKey: nil, sharedSecret: sharedSecret, maxSkip: 20, maxCache: 20, info: info)
        alice = try! DoubleRatchet(keyPair: nil, remotePublicKey: bob.publicKey, sharedSecret: sharedSecret, maxSkip: 20, maxCache: 20, info: info)
    }

    func testRatchetSteps() throws {
        let bobPublicKeySnapshot = bob.publicKey

        let message = "aliceToBob".bytes
        let encryptedMessage = try alice.encrypt(plaintext: message)
        let decryptedMessage = try bob.decrypt(message: encryptedMessage)
        XCTAssertEqual(message, decryptedMessage)
        XCTAssertNotEqual(bob.publicKey, bobPublicKeySnapshot)

        let alicePublicKeySnapshot = alice.publicKey

        let response = "bobToAlice".bytes
        let encryptedResponse = try bob.encrypt(plaintext: response)
        let decryptedResponse = try alice.decrypt(message: encryptedResponse)
        XCTAssertEqual(response, decryptedResponse)
        XCTAssertNotEqual(alice.publicKey, alicePublicKeySnapshot)
    }

    func testUnidirectionalConversation() throws {
        let alicePublicKeySnapshot = alice.publicKey

        for _ in 0...1 {
            let message = "aliceToBob".bytes
            let encryptedMessage = try alice.encrypt(plaintext: message)
            let decryptedMessage = try bob.decrypt(message: encryptedMessage)
            XCTAssertEqual(message, decryptedMessage)
        }

        XCTAssertEqual(alice.publicKey, alicePublicKeySnapshot)
    }

    func testLostMessages() throws {
        var delayedMessages: [Message] = []
        for i in 0...2 {
            let message = "aliceToBob\(i)".bytes
            let encryptedMessage = try alice.encrypt(plaintext: message)
            delayedMessages.append(encryptedMessage)
        }

        for i in (0...2).reversed() {
            let decryptedMessage = try bob.decrypt(message: delayedMessages[i])
            XCTAssertEqual(decryptedMessage, "aliceToBob\(i)".bytes)
        }
    }

    func testLostMessagesAndRatchetStep() throws {
        let message = "aliceToBob".bytes

        for _ in 0...1 {
            let encryptedMessage = try alice.encrypt(plaintext: message)
            _ = try bob.decrypt(message: encryptedMessage)
        }

        var delayedMessages: [Message] = []
        for i in 0...1 {
            if i == 1 {
                // Ratchet step
                let message = try bob.encrypt(plaintext: message)
                _ = try alice.decrypt(message: message)
            }
            let message = "aliceToBob\(i)".bytes
            let encryptedMessage = try alice.encrypt(plaintext: message)
            delayedMessages.append(encryptedMessage)
        }

        let successfulMessage = "aliceToBob2".bytes
        let successfulEncryptedRatchetMessage = try alice.encrypt(plaintext: successfulMessage)
        let successfulPlaintext = try bob.decrypt(message: successfulEncryptedRatchetMessage)
        XCTAssertEqual(successfulPlaintext, successfulMessage)

        for i in (0...1).reversed() {
            let decryptedMessage = try bob.decrypt(message: delayedMessages[i])
            XCTAssertEqual(decryptedMessage, "aliceToBob\(i)".bytes)
        }
    }

    func testExceedMaxSkipMessages() throws {
            bob = try DoubleRatchet(keyPair: nil, remotePublicKey: nil, sharedSecret: sharedSecret, maxSkip: 1, maxCache: 2, info: info)
            alice = try DoubleRatchet(keyPair: nil, remotePublicKey: bob.publicKey, sharedSecret: sharedSecret, maxSkip: 1, maxCache: 2, info: info)

            for _ in 0...1 {
                _ = try alice.encrypt(plaintext: "Message".bytes)
            }

            let encryptedMessage = try alice.encrypt(plaintext: "Message".bytes)

        do {
            _ = try bob.decrypt(message: encryptedMessage)
            XCTFail()
        } catch {
            guard case DRError.exceedMaxSkip = error else {
                XCTFail()
                return
            }
        }
    }

    func testExceedMaxCacheMessageKeys() throws {
        bob = try DoubleRatchet(keyPair: nil, remotePublicKey: nil, sharedSecret: sharedSecret, maxSkip: 20, maxCache: 1, info: info)
        alice = try DoubleRatchet(keyPair: nil, remotePublicKey: bob.publicKey, sharedSecret: sharedSecret, maxSkip: 20, maxCache: 1, info: info)

        var delayedMessages: [Message] = []

        for i in 0...2 {
            let message = "aliceToBob\(i)"
            let encryptedMessage = try alice.encrypt(plaintext: message.bytes)
            delayedMessages.append(encryptedMessage)
        }

        for i in (1...2).reversed() {
            let plaintext = try bob.decrypt(message: delayedMessages[i])
            XCTAssertEqual(plaintext, "aliceToBob\(i)".bytes)
        }

        do {
            _ = try bob.decrypt(message: delayedMessages[0])
            XCTFail()
        } catch {
            guard case DRError.discardOldMessage = error else {
                XCTFail(error.localizedDescription)
                return
            }
        }
    }

    func testEncryptAssociatedData() throws {
        let message = "aliceToBob".bytes
        let associatedData = "AD".bytes
        let encryptedMessage = try alice.encrypt(plaintext: message, associatedData: associatedData)
        let decryptedMessage = try bob.decrypt(message: encryptedMessage, associatedData: associatedData)
        XCTAssertEqual(message, decryptedMessage)
    }

    func testReinitializeSession() throws {
        bob = try DoubleRatchet(keyPair: nil, remotePublicKey: nil, sharedSecret: sharedSecret, maxSkip: 20, maxCache: 1, info: info)
        alice = try DoubleRatchet(keyPair: nil, remotePublicKey: bob.publicKey, sharedSecret: sharedSecret, maxSkip: 20, maxCache: 1, info: info)

        let message = "aliceToBob"
        let encryptedMessage = try alice.encrypt(plaintext: message.bytes)
        let plaintext = try bob.decrypt(message: encryptedMessage)
        XCTAssertEqual(plaintext.utf8String!, message)

        bob = DoubleRatchet(sessionState: bob.sessionState)
        alice = DoubleRatchet(sessionState: alice.sessionState)

        let messageAliceToBob = "aliceToBob"
        let encryptedMessageAliceToBob = try alice.encrypt(plaintext: messageAliceToBob.bytes)
        let plaintextAliceToBob = try bob.decrypt(message: encryptedMessageAliceToBob)
        XCTAssertEqual(plaintextAliceToBob.utf8String!, messageAliceToBob)

        let messageBobToAlice = "bobToAlice"
        let encryptedMessageBobToAlice = try bob.encrypt(plaintext: messageBobToAlice.bytes)
        let plaintextBobToAlice = try alice.decrypt(message: encryptedMessageBobToAlice)
        XCTAssertEqual(plaintextBobToAlice.utf8String!, messageBobToAlice)
    }
    
    func testMessageHeaderEncoding() throws {
        let pubKey = Sodium().utils.hex2bin("0efd0d78c9ba26b39588848ddf69b02807fb85916c2b004d7af759f932544443")!
        let header = Header(publicKey: pubKey, numberOfMessagesInPreviousSendingChain: 1234567890, messageNumber: 9876543210)
        
        let headerBytesAre = try header.bytes()
        let headerBytesShouldBe = Sodium().utils.hex2bin("0efd0d78c9ba26b39588848ddf69b02807fb85916c2b004d7af759f93254444300000000499602d2000000024cb016ea")!
        XCTAssertEqual(headerBytesAre, headerBytesShouldBe)
    }

    static var allTests = [
        ("testRatchetSteps", testRatchetSteps),
        ("testUnidirectionalConversation", testUnidirectionalConversation),
        ("testLostMessages", testLostMessages),
        ("testLostMessagesAndRatchetStep", testLostMessagesAndRatchetStep),
        ("testExceedMaxSkipMessages", testExceedMaxSkipMessages),
        ("testExceedMaxCacheMessageKeys", testExceedMaxCacheMessageKeys),
        ("testEncryptAssociatedData", testEncryptAssociatedData),
        ("testReinitializeSession", testReinitializeSession),
        ("testMessageHeaderEncoding", testMessageHeaderEncoding),
    ]
}
