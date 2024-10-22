const ls = window.libsignal;
const store = new window.SignalProtocolStore(); // This stores cryptographic keys and session data for Signal protocol.
const KeyHelper = ls.KeyHelper;


async function generatePreKeys(registrationId) {

}

async function initKeyForUser(registrationId, deviceId, numberOfPreKeys = 10) {
    const user = {
        registrationId, // Unique registration ID of the user (used in Signal protocol).
        deviceId, // Unique device ID of the user.
        identityKeyPair: {}, // User's identity key pair (generated using Signal protocol).
        preKeyObjects: [], // Pre-key objects stored locally.
        preKeyObjectsToSend: [], // Pre-key objects formatted for sending to the server.
        signedPreKeyObject: {} // A signed pre-key object (part of Signal protocol key exchange).
    }

    store.put('registrationId', user.registrationId); // Store the registration ID in the Signal store.
    user.identityKeyPair = await KeyHelper.generateIdentityKeyPair(); // Generate identity key pair.
    store.put('identityKey', user.identityKeyPair); // Store the identity key pair.

    const listOfPreKeysPromise = [];

    // Generate a list of promises to create `numberOfPreKeys` pre-keys.
    for (let i = 0; i < numberOfPreKeys; i++) {
        listOfPreKeysPromise.push(KeyHelper.generatePreKey(registrationId + i + 1)); // Pre-keys need to be unique.
    }

    const preKeys = await Promise.all(listOfPreKeysPromise); // Wait until all pre-keys are generated.

    // For each pre-key, store it locally and prepare it for sending to the server.
    preKeys.forEach(preKey => {
        let preKeyObject = {
            keyId: preKey.keyId, // Unique key ID for this pre-key.
            keyPair: preKey.keyPair // Key pair (public/private) of the pre-key.
        };
        user.preKeyObjects.push(preKeyObject); // Store locally.
        store.storePreKey(preKeyObject.keyId, preKeyObject.keyPair); // Store pre-key in the local Signal store.

        // Format the pre-key for sending to the server (only the public key is needed).
        let preKeyObjectToSend = {
            id: preKeyObject.keyId,
            key: window.arrBuffToBase64(preKeyObject.keyPair.pubKey) // Convert the public key to base64.
        };
        user.preKeyObjectsToSend.push(preKeyObjectToSend); // Add to the list of pre-keys to send to the server.
    });

    // Generate a signed pre-key (a longer-term key) used to sign other keys.
    const signedPreKey = await KeyHelper.generateSignedPreKey(user.identityKeyPair, 5);
    user.signedPreKeyObject = {
        keyId: signedPreKey.keyId,
        keyPair: signedPreKey.keyPair,
        signature: signedPreKey.signature // The signed pre-key signature.
    }
    await store.storeSignedPreKey(signedPreKey.keyId, user.signedPreKeyObject.keyPair); // Store the signed pre-key locally.

    return {
        type: 'init', // Initialization request to register keys on the server.
        deviceId: user.deviceId,
        registrationId: user.registrationId,
        identityKey: window.arrBuffToBase64(user.identityKeyPair.pubKey), // Convert public key to base64 for transmission.
        signedPreKey: {
            id: user.signedPreKeyObject.keyId,
            key: window.arrBuffToBase64(user.signedPreKeyObject.keyPair.pubKey), // Signed pre-key public key in base64.
            signature: window.arrBuffToBase64(user.signedPreKeyObject.signature) // Signature for the signed pre-key.
        },
        preKeys: user.preKeyObjectsToSend // Array of pre-keys formatted for sending to the server.
    }
}

(async () => {
    const registrationId = 1; // Unique registration ID for the user.
    const deviceId = 1; // Unique device ID for the user.

    const user1Keys = await initKeyForUser(registrationId, deviceId); // Initialize the user and generate keys.

    const registrationId2 = 2; // Unique registration ID for the user.
    const deviceId2 = 2; // Unique device ID for the user.

    const user2Keys = await initKeyForUser(registrationId2, deviceId2); // Initialize the user and generate keys.

    const user2PreKey = user2Keys.preKeys[0];

    const preparedUser2Keys = {
        registrationId: user2Keys.registrationId,
        identityKey: window.base64ToArrBuff(user2Keys.identityKey), // Convert base64 back to array buffer for identity key.
        signedPreKey: {
            keyId: user2Keys.signedPreKey.id,
            publicKey: window.base64ToArrBuff(user2Keys.signedPreKey.key),
            signature: window.base64ToArrBuff(user2Keys.signedPreKey.signature)
        },
        preKey: {
            keyId: user2PreKey.id,
            publicKey: window.base64ToArrBuff(user2PreKey.key)
        }
    };


    let recipientAddress = new ls.SignalProtocolAddress(registrationId2, deviceId2); // Address of the recipient.
    let sessionBuilder = new ls.SessionBuilder(store, recipientAddress); // Initialize session builder with the recipient's address.
    await sessionBuilder.processPreKey(preparedUser2Keys); // Process the pre-key for the session.

    let message = 'Hello, world!'; // Message to send.


    let messageObject = {
        messageTo: {
            registrationId: registrationId2, // The recipient's registration ID.
            deviceId: deviceId2 // The recipient's device ID.
        },
        messageFrom: {
            registrationId: registrationId, // The sender's registration ID.
            deviceId: deviceId // The sender's device ID.
        },
        ciphertextMessage: 'Invalid ciphertext', // Placeholder for encrypted message.
    };

    let signalMessageToAddress = new ls.SignalProtocolAddress(messageObject.messageTo.registrationId, messageObject.messageTo.deviceId); // Address for the message.
    let sessionCipher = new ls.SessionCipher(store, signalMessageToAddress); // Initialize the cipher for encryption.
    messageObject.ciphertextMessage = await sessionCipher.encrypt(message); // Encrypt the message using Signal protocol.

    console.log('Encrypted message:', messageObject.ciphertextMessage);

    let signalMessageFromAddress = new ls.SignalProtocolAddress(messageObject.messageFrom.registrationId, messageObject.messageFrom.deviceId); // Address of the sender.
    let sessionCipherEncr = new ls.SessionCipher(store, signalMessageFromAddress); // Initialize the cipher for decryption.
    const plaintext = await sessionCipherEncr.decryptPreKeyWhisperMessage(messageObject.ciphertextMessage.body, 'binary'); // Decrypt the incoming message.
    console.log(window.util.toString(plaintext));

    console.log('-----------------------------------');
    console.log(await sessionCipher.hasOpenSession())
    console.log('-----------------------------------');

    const message2 = await sessionCipher.encrypt("!!!!message 2!!!!");
    console.log('Encrypted message:', message2);

    const plaintext2 = await sessionCipherEncr.decryptPreKeyWhisperMessage(message2.body, 'binary'); // Decrypt the incoming message.
    console.log("message 2",window.util.toString(plaintext2));



    const message3 = await sessionCipher.encrypt("!!!!message 3!!!!");
    console.log('Encrypted message:', message3);

    const plaintext3 = await sessionCipherEncr.decryptPreKeyWhisperMessage(message3.body, 'binary'); // Decrypt the incoming message.
    console.log("message 2",window.util.toString(plaintext3));
})();