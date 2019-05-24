//
//  Copyright © 2019 Anbion. All rights reserved.
//

import Sodium
import HKDF

public typealias KeyPair = KeyExchange.KeyPair
public typealias PublicKey = KeyExchange.PublicKey
public typealias MessageKey = Bytes

public class DoubleRatchet {
    private let sodium = Sodium()

    public let maxSkip: Int
    public let maxCache: Int

    private var rootChain: RootChain
    private var sendingChain: MessageChain
    private var receivingChain: MessageChain

    private var sendMessageNumber: Int
    private var receivedMessageNumber: Int
    private var previousSendingChainLength: Int
    private var skippedMessageKeys: [MessageIndex: MessageKey]
    private var messageKeyCache: [MessageIndex]

    public var publicKey: PublicKey {
        return rootChain.keyPair.publicKey
    }

    public struct MessageIndex: Hashable {
        let publicKey: PublicKey
        let messageNumber: Int
    }

    public var sessionState: SessionState {
        return SessionState(info: rootChain.info, maxSkip: maxSkip, maxCache: maxCache, rootKey: rootChain.rootKey, rootChainKeyPair: rootChain.keyPair, rootChainRemotePublicKey: rootChain.remotePublicKey, sendingChainKey: sendingChain.chainKey, receivingChainKey: receivingChain.chainKey, sendMessageNumber: sendMessageNumber, receivedMessageNumber: receivedMessageNumber, previousSendingChainLength: previousSendingChainLength, skippedMessageKeys: skippedMessageKeys, messageKeyCache: messageKeyCache)
    }

    public init(keyPair: KeyPair?, remotePublicKey: PublicKey?, sharedSecret: Bytes, maxSkip: Int, maxCache: Int, info: String) throws {
        guard sharedSecret.count == 32 else {
            throw DRError.invalidSharedSecret
        }

        self.maxSkip = maxSkip
        self.maxCache = maxCache

        guard let keyPair = keyPair ?? Sodium().keyExchange.keyPair() else {
            throw DRError.dhKeyGenerationFailed
        }

        self.rootChain = RootChain(keyPair: keyPair, remotePublicKey: remotePublicKey, rootKey: sharedSecret, info: info)
        self.sendingChain = MessageChain()
        self.receivingChain = MessageChain()

        self.sendMessageNumber = 0
        self.receivedMessageNumber = 0
        self.previousSendingChainLength = 0
        self.skippedMessageKeys = [:]
        self.messageKeyCache = []

        if remotePublicKey != nil {
            sendingChain.chainKey = try self.rootChain.ratchetStep(side: .sending)
        }
    }

    public init(sessionState: SessionState) {
        self.maxSkip = sessionState.maxSkip
        self.maxCache = sessionState.maxCache

        self.rootChain = RootChain(keyPair: sessionState.rootChainKeyPair, remotePublicKey: sessionState.rootChainRemotePublicKey, rootKey: sessionState.rootKey, info: sessionState.info)
        self.sendingChain = MessageChain(chainKey: sessionState.sendingChainKey)
        self.receivingChain = MessageChain(chainKey: sessionState.receivingChainKey)

        self.sendMessageNumber = sessionState.sendMessageNumber
        self.receivedMessageNumber = sessionState.receivedMessageNumber
        self.previousSendingChainLength = sessionState.previousSendingChainLength
        self.skippedMessageKeys = sessionState.skippedMessageKeys
        self.messageKeyCache = sessionState.messageKeyCache
    }

    public func encrypt(plaintext: Bytes, associatedData: Bytes? = nil) throws -> Message {
        let messageKey = try sendingChain.nextMessageKey()
        let header = Header(publicKey: rootChain.keyPair.publicKey, numberOfMessagesInPreviousSendingChain: previousSendingChainLength, messageNumber: sendMessageNumber)
        sendMessageNumber += 1

        var headerData = try header.bytes()
        if let associatedData = associatedData {
            headerData.append(contentsOf: associatedData)
        }

        guard let cipher: Bytes = sodium.aead.xchacha20poly1305ietf.encrypt(message: plaintext, secretKey: messageKey, additionalData: headerData) else {
            throw DRError.encryptionFailed
        }
        return Message(header: header, cipher: cipher)
    }

    public func decrypt(message: Message, associatedData: Bytes? = nil) throws -> Bytes {
        if let plaintext = try decryptSkippedMessage(message, associatedData: associatedData) {
            return plaintext
        }

        if message.header.messageNumber < receivedMessageNumber {
            throw DRError.discardOldMessage
        }

        let remotePublicKey = rootChain.remotePublicKey ?? message.header.publicKey
        if message.header.publicKey != rootChain.remotePublicKey {
            try skipReceivedMessages(until: message.header.numberOfMessagesInPreviousSendingChain, remotePublicKey: remotePublicKey)
            try doubleRatchetStep(publicKey: message.header.publicKey)
        }

        try skipReceivedMessages(until: message.header.messageNumber, remotePublicKey: message.header.publicKey)

        let messageKey = try receivingChain.nextMessageKey()
        let plaintext = try decrypt(message: message, key: messageKey, associatedData: associatedData)
        receivedMessageNumber += 1
        return plaintext
    }

    private func decryptSkippedMessage(_ message: Message, associatedData: Bytes?) throws -> Bytes? {
        let skippedMessageIndex = MessageIndex(publicKey: message.header.publicKey, messageNumber: message.header.messageNumber)
        guard let messageKey = skippedMessageKeys[skippedMessageIndex] else { return nil }

        let plaintext = try decrypt(message: message, key: messageKey, associatedData: associatedData)

        skippedMessageKeys[skippedMessageIndex] = nil
        messageKeyCache.removeAll { $0 == skippedMessageIndex }

        return plaintext
    }

    private func decrypt(message: Message, key: MessageKey, associatedData: Bytes?) throws -> Bytes {
        var headerData = try message.header.bytes()
        if let associatedData = associatedData {
            headerData.append(contentsOf: associatedData)
        }

        guard let plaintext = sodium.aead.xchacha20poly1305ietf.decrypt(nonceAndAuthenticatedCipherText: message.cipher, secretKey: key, additionalData: headerData) else {
            throw DRError.decryptionFailed
        }
        return plaintext
    }

    private func skipReceivedMessages(until nextMessageNumber: Int, remotePublicKey: PublicKey) throws {
        guard nextMessageNumber - receivedMessageNumber <= maxSkip else {
            throw DRError.exceedMaxSkip
        }

        while receivedMessageNumber < nextMessageNumber {
            let skippedMessageKey = try receivingChain.nextMessageKey()
            let skippedMessageIndex = MessageIndex(publicKey: remotePublicKey, messageNumber: receivedMessageNumber)

            skippedMessageKeys[skippedMessageIndex] = skippedMessageKey
            messageKeyCache.append(skippedMessageIndex)
            while messageKeyCache.count > maxCache {
                let removedIndex = messageKeyCache.removeFirst()
                skippedMessageKeys[removedIndex] = nil
            }
            
            receivedMessageNumber += 1
        }
    }

    private func doubleRatchetStep(publicKey: KeyExchange.PublicKey) throws {
        previousSendingChainLength = sendMessageNumber
        sendMessageNumber = 0
        receivedMessageNumber = 0

        rootChain.remotePublicKey = publicKey

        receivingChain.chainKey = try rootChain.ratchetStep(side: .receiving)

        guard let newKeyPair = sodium.keyExchange.keyPair() else {
            throw DRError.dhKeyGenerationFailed
        }
        rootChain.keyPair = newKeyPair

        sendingChain.chainKey = try rootChain.ratchetStep(side: .sending)
    }
}
