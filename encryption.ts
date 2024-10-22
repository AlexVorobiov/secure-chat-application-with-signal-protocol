import {
    PrivateKey,
    PublicKey,
    SignalMessage,
    PreKeySignalMessage,
    SessionStore,
    IdentityKeyStore,
    PreKeyStore,
    SignedPreKeyStore,
    KyberPreKeyStore,
    ProtocolAddress,
    CiphertextMessage,
    signalEncrypt,
    signalDecrypt,
    signalDecryptPreKey,
    SessionRecord,
    Direction,
    processPreKeyBundle,
    PreKeyBundle,
    KyberPreKeyRecord,
    SignedPreKeyRecord,
    PreKeyRecord,
} from '@signalapp/libsignal-client';

// Helper function to generate a unique key for ProtocolAddress
function getAddressKey(address: ProtocolAddress): string {
    // Assuming ProtocolAddress has 'getName()' and 'getDeviceId()' methods
    return `${address.name()}.${address.deviceId()}`;
}

// ---- Receiver Side ----

// Generate identity key pair for the receiver
const receiverIdentityKeyPair = PrivateKey.generate();
const receiverIdentityPrivateKey = receiverIdentityKeyPair;
const receiverIdentityPublicKey = receiverIdentityKeyPair.getPublicKey();

// Generate the pre-key and signed pre-key for the receiver
const receiverPreKey = PrivateKey.generate();
const receiverPreKeyPublic = receiverPreKey.getPublicKey();
const receiverPreKeyId = 1;

const receiverSignedPreKey = PrivateKey.generate();
const receiverSignedPreKeyPublic = receiverSignedPreKey.getPublicKey();
const receiverSignedPreKeyId = 1;

// Generate the signed pre-key signature using the receiver's identity key
const receiverSignedPreKeySignature = receiverIdentityPrivateKey.sign(receiverSignedPreKeyPublic.serialize());

// Implement the PreKeyStore for the receiver
class ReceiverPreKeyStore extends PreKeyStore {
    private preKeys: Map<number, PreKeyRecord> = new Map();

    async savePreKey(id: number, record: PreKeyRecord): Promise<void> {
        this.preKeys.set(id, record);
    }

    async getPreKey(id: number): Promise<PreKeyRecord> {
        const record = this.preKeys.get(id);
        if (!record) {
            throw new Error(`No pre-key found for id ${id}`);
        }
        return record;
    }

    async removePreKey(id: number): Promise<void> {
        this.preKeys.delete(id);
    }
}

// Implement the SignedPreKeyStore for the receiver
class ReceiverSignedPreKeyStore extends SignedPreKeyStore {
    private signedPreKeys: Map<number, SignedPreKeyRecord> = new Map();

    async saveSignedPreKey(id: number, record: SignedPreKeyRecord): Promise<void> {
        this.signedPreKeys.set(id, record);
    }

    async getSignedPreKey(id: number): Promise<SignedPreKeyRecord> {
        const record = this.signedPreKeys.get(id);
        if (!record) {
            throw new Error(`No signed pre-key found for id ${id}`);
        }
        return record;
    }
}

// Implement the IdentityKeyStore for the receiver
class ReceiverIdentityKeyStore extends IdentityKeyStore {
    private identityKeys: Map<string, PublicKey> = new Map();

    async getIdentityKey(): Promise<PrivateKey> {
        return receiverIdentityPrivateKey;
    }

    async getLocalRegistrationId(): Promise<number> {
        return 12345;
    }

    async saveIdentity(address: ProtocolAddress, key: PublicKey): Promise<boolean> {
        const keyString = getAddressKey(address);
        this.identityKeys.set(keyString, key);
        return true;
    }

    async isTrustedIdentity(address: ProtocolAddress, key: PublicKey, direction: Direction): Promise<boolean> {
        return true;
    }

    async getIdentity(address: ProtocolAddress): Promise<PublicKey | null> {
        const keyString = getAddressKey(address);
        return this.identityKeys.get(keyString) || null;
    }
}

// Implement the SessionStore for the receiver
class ReceiverSessionStore extends SessionStore {
    private sessions: Map<string, SessionRecord> = new Map();

    async saveSession(address: ProtocolAddress, record: SessionRecord): Promise<void> {
        const key = getAddressKey(address);
        console.log(`Receiver saveSession called with key: ${key}`);
        this.sessions.set(key, record);
    }

    async getSession(address: ProtocolAddress): Promise<SessionRecord | null> {
        const key = getAddressKey(address);
        const session = this.sessions.get(key) || null;
        console.log(`Receiver getSession called with key: ${key} - Found: ${session !== null}`);
        return session;
    }

    async getExistingSessions(addresses: ProtocolAddress[]): Promise<SessionRecord[]> {
        return addresses
            .map(addr => this.sessions.get(getAddressKey(addr))!)
            .filter(Boolean);
    }
}

// Implement the KyberPreKeyStore (stub implementation)
class SimpleKyberPreKeyStore extends KyberPreKeyStore {
    async saveKyberPreKey(kyberPreKeyId: number, record: KyberPreKeyRecord): Promise<void> {
        // No operation needed as we're not using Kyber keys
    }

    async getKyberPreKey(kyberPreKeyId: number): Promise<KyberPreKeyRecord> {
        throw new Error('No Kyber pre-key found');
    }

    async markKyberPreKeyUsed(kyberPreKeyId: number): Promise<void> {
        // No operation needed as we're not using Kyber keys
    }
}

// Initialize the receiver's stores
const receiverSessionStore = new ReceiverSessionStore();
const receiverIdentityStore = new ReceiverIdentityKeyStore();
const receiverPreKeyStore = new ReceiverPreKeyStore();
const receiverSignedPreKeyStore = new ReceiverSignedPreKeyStore();
const receiverKyberPreKeyStore = new SimpleKyberPreKeyStore(); // Stub implementation

// Save receiver's pre-keys and signed pre-keys in their stores


// Create receiver's pre-key bundle to be shared with the sender
const receiverPreKeyBundle = PreKeyBundle.new(
    12345, // registrationId
    1, // deviceId
    receiverPreKeyId,
    receiverPreKeyPublic,
    receiverSignedPreKeyId,
    receiverSignedPreKeyPublic,
    receiverSignedPreKeySignature,
    receiverIdentityPublicKey
);

// Receiver's address


// ---- Sender Side ----

// Generate identity key pair for the sender
const senderIdentityKeyPair = PrivateKey.generate();
const senderIdentityPrivateKey = senderIdentityKeyPair;
const senderIdentityPublicKey = senderIdentityKeyPair.getPublicKey();

// Implement the IdentityKeyStore for the sender
class SenderIdentityKeyStore extends IdentityKeyStore {
    private identityKeys: Map<string, PublicKey> = new Map();

    async getIdentityKey(): Promise<PrivateKey> {
        return senderIdentityPrivateKey;
    }

    async getLocalRegistrationId(): Promise<number> {
        return 67890;
    }

    async saveIdentity(address: ProtocolAddress, key: PublicKey): Promise<boolean> {
        const keyString = getAddressKey(address);
        this.identityKeys.set(keyString, key);
        return true;
    }

    async isTrustedIdentity(address: ProtocolAddress, key: PublicKey, direction: Direction): Promise<boolean> {
        return true;
    }

    async getIdentity(address: ProtocolAddress): Promise<PublicKey | null> {
        const keyString = getAddressKey(address);
        return this.identityKeys.get(keyString) || null;
    }
}

// Implement the SessionStore for the sender
class SenderSessionStore extends SessionStore {
    private sessions: Map<string, SessionRecord> = new Map();

    async saveSession(address: ProtocolAddress, record: SessionRecord): Promise<void> {
        const key = getAddressKey(address);
        console.log(`Receiver saveSession called with key: ${key}`);
        this.sessions.set(key, record);
    }

    async getSession(address: ProtocolAddress): Promise<SessionRecord | null> {
        const key = getAddressKey(address);
        const session = this.sessions.get(key) || null;
        console.log(`Receiver getSession called with key: ${key} - Found: ${session !== null}`);
        return session;
    }

    async getExistingSessions(addresses: ProtocolAddress[]): Promise<SessionRecord[]> {
        return addresses
            .map(addr => this.sessions.get(getAddressKey(addr))!)
            .filter(Boolean);
    }
}

// Initialize the sender's stores
const senderSessionStore = new SenderSessionStore();
const senderIdentityStore = new SenderIdentityKeyStore();

// Sender's address
const senderAddress = ProtocolAddress.new('sender@example.com', 1);
const receiverAddress = ProtocolAddress.new('receiver@example.com', 1);

(async () => {
    const receiverPreKeyRecord = PreKeyRecord.new(
        receiverPreKeyId,
        receiverPreKeyPublic,
        receiverPreKey
    );
    await receiverPreKeyStore.savePreKey(receiverPreKeyId, receiverPreKeyRecord);

    const receiverSignedPreKeyRecord = SignedPreKeyRecord.new(
        receiverSignedPreKeyId,
        Date.now(),
        receiverSignedPreKeyPublic,
        receiverSignedPreKey,
        receiverSignedPreKeySignature
    );
    await receiverSignedPreKeyStore.saveSignedPreKey(
        receiverSignedPreKeyId,
        receiverSignedPreKeyRecord
    );
    // Sender processes the receiver's pre-key bundle to establish a session
    await processPreKeyBundle(
        receiverPreKeyBundle,
        receiverAddress,
        senderSessionStore,
        senderIdentityStore
    );

    // Sender encrypts a message to the receiver
    const plaintextMessage = Buffer.from('Hello, Signal Protocol!');
    const ciphertextMessage = await signalEncrypt(
        plaintextMessage,
        receiverAddress,
        senderSessionStore,
        senderIdentityStore
    );

    const sessionRecord = await senderSessionStore.getSession(receiverAddress);
    if (sessionRecord) {
        await senderSessionStore.saveSession(receiverAddress, sessionRecord);
    }

    console.log('Encrypted Message:', ciphertextMessage.serialize().toString('base64'));
    console.log('Message Type:', ciphertextMessage.type()); // Should output 3

    // ---- Receiver Side: Decrypting the Message ----

    // Receiver checks message type and deserializes accordingly
    if (ciphertextMessage.type() === 3) {
        // Deserialize ciphertextMessage into PreKeySignalMessage
        const preKeySignalMessage = PreKeySignalMessage.deserialize(
            ciphertextMessage.serialize()
        );

        // Receiver decrypts the PreKeySignalMessage
        const decryptedMessage = await signalDecryptPreKey(
            preKeySignalMessage,
            senderAddress,
            receiverSessionStore,
            receiverIdentityStore,
            receiverPreKeyStore,
            receiverSignedPreKeyStore,
            receiverKyberPreKeyStore // Stub implementation
        );

        const sessionRecordReceiver = await receiverSessionStore.getSession(senderAddress);
        if (sessionRecordReceiver) {
            await receiverSessionStore.saveSession(senderAddress, sessionRecordReceiver);
        }

        console.log('Decrypted Message:', decryptedMessage.toString());
    } else {
        // For subsequent messages (message type 2)
        const decryptedMessage = await signalDecrypt(
            ciphertextMessage,
            senderAddress,
            receiverSessionStore,
            receiverIdentityStore
        );

        console.log('Decrypted Message:', decryptedMessage.toString());
    }

    // Sender encrypts a second message
    const plaintextMessage2 = Buffer.from('This is the second message.');
    const ciphertextMessage2 = await signalEncrypt(
        plaintextMessage2,
        receiverAddress,
        senderSessionStore,
        senderIdentityStore
    );
    const sessionRecord2 = await senderSessionStore.getSession(receiverAddress);
    if (sessionRecord2) {
        await senderSessionStore.saveSession(receiverAddress, sessionRecord);
    }

    console.log('Encrypted second Message 2:', ciphertextMessage2.serialize().toString('base64'));
    console.log('Message second Type:', ciphertextMessage2.type()); // Should output 2

    // ---- Receiver Side: Decrypting the Second Message ----

    // Receiver checks message type and deserializes accordingly
    if (ciphertextMessage2.type() === 3) {
        // Deserialize ciphertextMessage into PreKeySignalMessage
        const preKeySignalMessage = PreKeySignalMessage.deserialize(
            ciphertextMessage2.serialize()
        );

        // Receiver decrypts the PreKeySignalMessage
        const decryptedMessage = await signalDecryptPreKey(
            preKeySignalMessage,
            senderAddress,
            receiverSessionStore,
            receiverIdentityStore,
            receiverPreKeyStore,
            receiverSignedPreKeyStore,
            receiverKyberPreKeyStore // Stub implementation
        );

        console.log('Decrypted Message 2:', decryptedMessage.toString());
    } else {
        // For subsequent messages (message type 2)
        const decryptedMessage = await signalDecrypt(
            ciphertextMessage2,
            senderAddress,
            receiverSessionStore,
            receiverIdentityStore
        );

        console.log('Decrypted Message 2:', decryptedMessage.toString());
    }
})();