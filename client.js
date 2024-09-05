// Import Signal protocol library and initialize the Signal protocol store.
const ls = window.libsignal;
const store = new window.SignalProtocolStore(); // This stores cryptographic keys and session data for Signal protocol.
const KeyHelper = ls.KeyHelper; // Helper from Signal protocol to generate keys and pre-keys.
const serverBaseUrl = window.location.href; // Base URL for sending and receiving data from the server.

const numberOfPreKeys = 10; // Number of pre-keys to generate and send to the server.

const user = {
    registrationId: 0, // Unique registration ID of the user (used in Signal protocol).
    deviceId: 0, // Unique device ID of the user.
    identityKeyPair: {}, // User's identity key pair (generated using Signal protocol).
    preKeyObjects: [], // Pre-key objects stored locally.
    preKeyObjectsToSend: [], // Pre-key objects formatted for sending to the server.
    signedPreKeyObject: {} // A signed pre-key object (part of Signal protocol key exchange).
}

const myContacts = {}; // Store contacts and their associated cryptographic data for messaging.

// Build a unique identifier for each user based on registrationId and deviceId.
function buildUserUniqueID(registrationId, deviceId) {
    return `${registrationId}_${deviceId}`;
}

// Send user's generated keys (identity key, signed pre-key, and pre-keys) to the server for storage and key exchange.
async function sendKeysToServer() {
    let url = serverBaseUrl + 'send'; // Endpoint on the server to send the keys.
    let requestObject = {
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

    return window.sendRequest(url, requestObject); // Make the actual network request to the server.
}

// Generate pre-keys (short-term keys used for establishing secure communication) for the user.
async function generatePreKeys(registrationId) {
    let listOfPreKeysPromise = [];

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
    store.storeSignedPreKey(signedPreKey.keyId, user.signedPreKeyObject.keyPair); // Store the signed pre-key locally.
}

// Initialize the user by generating keys and sending them to the server.
async function initUser(registrationId, deviceId) {
    user.registrationId = registrationId; // Set the user's registration ID.
    user.deviceId = deviceId; // Set the user's device ID.

    store.put('registrationId', user.registrationId); // Store the registration ID in the Signal store.
    user.identityKeyPair = await KeyHelper.generateIdentityKeyPair(); // Generate identity key pair.
    store.put('identityKey', user.identityKeyPair); // Store the identity key pair.

    await generatePreKeys(user.registrationId); // Generate and store pre-keys.
    await sendKeysToServer(); // Send the generated keys to the server.

    initSocketConnection(); // Start the socket connection for real-time communication.
}

// Setup a session with another user by processing their pre-key bundle and building a session using Signal protocol.
async function setupSession(processPreKeyObject, incomingDeviceIdStr) {
    let recipientAddress = new ls.SignalProtocolAddress(processPreKeyObject.registrationId, incomingDeviceIdStr); // Address of the recipient.
    let sessionBuilder = new ls.SessionBuilder(store, recipientAddress); // Initialize session builder with the recipient's address.
    await sessionBuilder.processPreKey(processPreKeyObject); // Process the pre-key for the session.

    // Add contact to myContacts using a unique identifier.
    myContacts[buildUserUniqueID(processPreKeyObject.registrationId, incomingDeviceIdStr)] = {
        deviceId: parseInt(incomingDeviceIdStr),
        preKeyObject: processPreKeyObject
    };
}

// Fetch another user's keys from the server.
async function getChatMemberKeys(registrationId, deviceId) {
    let requestObject = {
        registrationId, // The registration ID of the user.
        deviceId // The device ID of the user.
    };
    let url = serverBaseUrl + 'get'; // Server endpoint to retrieve the keys.
    const res = await window.sendRequest(url, requestObject); // Send request to the server.

    if (res.error) {
        console.log(res.error); // If there's an error, log it.
        return;
    }

    // Process and format the received key bundle for the session.
    const processPreKeyObject = {
        registrationId: res.registrationId,
        identityKey: window.base64ToArrBuff(res.identityKey), // Convert base64 back to array buffer for identity key.
        signedPreKey: {
            keyId: res.signedPreKey.id,
            publicKey: window.base64ToArrBuff(res.signedPreKey.key),
            signature: window.base64ToArrBuff(res.signedPreKey.signature)
        },
        preKey: {
            keyId: res.preKey.id,
            publicKey: window.base64ToArrBuff(res.preKey.key)
        }
    };

    await setupSession(processPreKeyObject, deviceId); // Setup the session using the retrieved pre-keys.
}

// Encrypt a message and prepare it to be sent to the server.
async function sendMessageToServer(message, messageToObject) {
    let messageObject = {
        messageTo: {
            registrationId: messageToObject.preKeyObject.registrationId, // The recipient's registration ID.
            deviceId: messageToObject.deviceId // The recipient's device ID.
        },
        messageFrom: {
            registrationId: user.registrationId, // The sender's registration ID.
            deviceId: user.deviceId // The sender's device ID.
        },
        ciphertextMessage: 'Invalid ciphertext', // Placeholder for encrypted message.
    };

    let signalMessageToAddress = new ls.SignalProtocolAddress(messageObject.messageTo.registrationId, messageObject.messageTo.deviceId); // Address for the message.
    let sessionCipher = new ls.SessionCipher(store, signalMessageToAddress); // Initialize the cipher for encryption.
    messageObject.ciphertextMessage = await sessionCipher.encrypt(message); // Encrypt the message using Signal protocol.
    return messageObject; // Return the encrypted message object.
}

// Decrypt incoming messages.
async function processIncomingMessage(incomingMessageObj) {
    let signalMessageFromAddress = new ls.SignalProtocolAddress(incomingMessageObj.messageFrom.registrationId, incomingMessageObj.messageFrom.deviceId); // Address of the sender.
    let sessionCipher = new ls.SessionCipher(store, signalMessageFromAddress); // Initialize the cipher for decryption.
    const plaintext = await sessionCipher.decryptPreKeyWhisperMessage(incomingMessageObj.ciphertextMessage.body, 'binary'); // Decrypt the incoming message.
    return window.util.toString(plaintext); // Convert the decrypted message to a string.
}

// Message type constants used for socket events.
const MESSAGE_TYPES = {
    MESSAGE: 'message',
    WELCOME: 'welcome',
    CONNECTION: 'connection',
    DISCONNECT: 'disconnect',
    NEW_USER: 'new-user'
};

// Initialize the socket connection for real-time communication.
function initSocketConnection() {
    const socket = io.connect(serverBaseUrl, {
        query: {
            registrationId: user.registrationId,
            deviceId: user.deviceId
        }
    });

    // Handle the welcome message from the server.
    socket.on(MESSAGE_TYPES.WELCOME, (message) => {
        document.getElementById('messages').innerText = message;
    });

    // Handle when a new user joins the chat.
    socket.on(MESSAGE_TYPES.NEW_USER, async (message) => {
        document.getElementById('messages').innerText += `\n${message}`;
        const json = JSON.parse(message);
        await getChatMemberKeys(json.registrationId, json.deviceId); // Get keys for the new user and initialize session.
    });

    // Handle incoming messages.
    socket.on(MESSAGE_TYPES.MESSAGE, async (msg) => {
        const json = JSON.parse(msg);
        console.log(json);
        if (json.messageFrom.registrationId === user.registrationId && json.messageFrom.deviceId === user.deviceId) {
            return; // Ignore messages sent by the current user.
        }

        const senderUniqueID = buildUserUniqueID(json.messageFrom.registrationId, json.messageFrom.deviceId);
        if (!myContacts[senderUniqueID]) {
            console.log(`User not in contacts: ${senderUniqueID}`);
            await getChatMemberKeys(json.messageFrom.registrationId, json.messageFrom.deviceId); // Retrieve keys for unknown contacts.
        }

        const decryptedMsg = await processIncomingMessage(json); // Decrypt the incoming message.

        const messages = document.getElementById('messages');
        messages.innerText += `\n${decryptedMsg}`; // Display the decrypted message.
    });

    // Send a message when the send button is clicked.
    document.getElementById('sendButton').addEventListener('click', async () => {
        const input = document.getElementById('messageInput');
        for (const contact in myContacts) {
            const msg = await sendMessageToServer(input.value, myContacts[contact]); // Encrypt the message.
            socket.emit(MESSAGE_TYPES.MESSAGE, JSON.stringify(msg)); // Send the encrypted message over the socket.
        }

        input.value = ''; // Clear the input field.
    });
}

// Initialize the application once the DOM content has been fully loaded.
document.addEventListener('DOMContentLoaded', () => {
    // Setup socket connection and user initialization when the user clicks the connect button.
    document.getElementById('connectButton').addEventListener('click', async () => {
        const input = document.getElementById('userTokenInput');
        const token = parseInt(input.value ?? KeyHelper.generateRegistrationId(), 10); // Use input token or generate a new one.
        const deviceId = KeyHelper.generateRegistrationId(); // Generate a new device ID.

        await initUser(token, deviceId); // Initialize the user with registration and device ID.

        input.value = ''; // Clear the input field.
    });
});