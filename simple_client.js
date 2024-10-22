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

async function getUserKeys(registrationId, deviceId) {
    const user1Keys = await initKeyForUser(registrationId, deviceId); // Initialize the user and generate keys.

    const user1PreKey = user1Keys.preKeys[0];

    return {
        registrationId: user1Keys.registrationId,
        identityKey: window.base64ToArrBuff(user1Keys.identityKey), // Convert base64 back to array buffer for identity key.
        signedPreKey: {
            keyId: user1Keys.signedPreKey.id,
            publicKey: window.base64ToArrBuff(user1Keys.signedPreKey.key),
            signature: window.base64ToArrBuff(user1Keys.signedPreKey.signature)
        },
        preKey: {
            keyId: user1PreKey.id,
            publicKey: window.base64ToArrBuff(user1PreKey.key)
        }
    };
}

(async () => {
    const registrationId = 1; // Unique registration ID for the user.
    const deviceId = 1; // Unique device ID for the user.
    const device2Id = 2; // Unique device ID for the user.

    const preparedUser1Keys = await getUserKeys(registrationId, deviceId);
    //const preparedUser2Keys = await getUserKeys(registrationId, device2Id);


    let recipientAddress = new ls.SignalProtocolAddress(registrationId, deviceId); // Address of the recipient.
    let sessionBuilder = new ls.SessionBuilder(store, recipientAddress); // Initialize session builder with the recipient's address.
    await sessionBuilder.processPreKey(preparedUser1Keys); // Process the pre-key for the session.


    let recipientAddress2 = new ls.SignalProtocolAddress(registrationId, device2Id); // Address of the recipient.
    let sessionBuilder2 = new ls.SessionBuilder(store, recipientAddress2); // Initialize session builder with the recipient's address.
    const r = await sessionBuilder2.processPreKey(preparedUser1Keys); // Process the pre-key for the session.
    console.log(r)


    let message = 'Hello, world!'; // Message to send.

    let signalMessageToAddress = new ls.SignalProtocolAddress(registrationId, device2Id); // Address for the message.
    let sessionCipher = new ls.SessionCipher(store, signalMessageToAddress); // Initialize the cipher for encryption.
    const ciphertextMessage = await sessionCipher.encrypt(message); // Encrypt the message using Signal protocol.

    console.log('Encrypted message:', ciphertextMessage);

    let signalMessageFromAddress = new ls.SignalProtocolAddress(registrationId, deviceId);
    let sessionCipherEncryptor = new ls.SessionCipher(store, signalMessageFromAddress);


    const plaintext = await sessionCipherEncryptor.decryptPreKeyWhisperMessage(ciphertextMessage.body, 'binary'); // Decrypt the incoming message.
    console.log(window.util.toString(plaintext));

    console.log('-----------------------------------');
    console.log(await sessionCipher.hasOpenSession())
    console.log('-----------------------------------');

    const message2 = 'Hello, again!'; // Another message to send.
    const ciphertextMessage2 = await sessionCipher.encrypt(message2); // Encrypt the message using Signal protocol.

    console.log('Encrypted message:', ciphertextMessage2);

    const plaintext2 = await sessionCipherEncryptor.decryptPreKeyWhisperMessage(ciphertextMessage2.body, 'binary'); // Decrypt the incoming message.
    console.log(window.util.toString(plaintext2));


})();