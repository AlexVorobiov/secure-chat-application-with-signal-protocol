const express = require('express');
const http = require('http');
const socketIo = require('socket.io');

const app = express();
const server = http.createServer(app);
const io = socketIo(server);


app.use(express.json({strict: true}));

app.use(express.static(__dirname));

app.get('/', (req, res) => {
    res.sendFile(__dirname + '/index.html');
});

const MESSAGE_TYPES = {
    MESSAGE: 'message',
    WELCOME: 'welcome',
    CONNECTION: 'connection',
    DISCONNECT: 'disconnect',
    NEW_USER: 'new-user'
};

const connectedUsers = {};

function buildUserUniqueID(registrationId, deviceId){
    return `${registrationId}_${deviceId}`;
}


io
    .use(function(socket, next){
        console.log('Socket middleware');
        console.log(socket.handshake.query);
        const userUniqueID = buildUserUniqueID(socket.handshake.query.registrationId, socket.handshake.query.deviceId);
        connectedUsers[userUniqueID] = {
            socket: socket,
            registrationId: socket.handshake.query.registrationId,
            deviceId: socket.handshake.query.deviceId
        };
        socket.user = connectedUsers[userUniqueID];
        next();
    })
    .on(MESSAGE_TYPES.CONNECTION, (socket) => {
        socket.emit('welcome', 'Welcome to the WebSocket server!');
        console.log('User connected', socket.user.registrationId, socket.user.deviceId);
        socket.broadcast.emit(MESSAGE_TYPES.NEW_USER, JSON.stringify({
            registrationId: socket.user.registrationId,
            deviceId: socket.user.deviceId
        }));
        socket.on(MESSAGE_TYPES.MESSAGE, (msg) => {
            console.log('Message received:', msg);
            const jsonMsg = JSON.parse(msg);
            const userUniqueID = buildUserUniqueID(
                jsonMsg.messageTo.registrationId, jsonMsg.messageTo.deviceId
            );

            if(connectedUsers[userUniqueID]){
                connectedUsers[userUniqueID].socket.emit(MESSAGE_TYPES.MESSAGE, msg);
            }else{
                console.log('User not connected');
            }

            // Echo the message back to the client
            // io.emit('message', msg);
        });

        socket.on(MESSAGE_TYPES.DISCONNECT, () => {
            console.log('User disconnected');
        });
});

const PORT = process.env.PORT || 3010;

server.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});

app.post('/send', receiveKeys);
app.post('/get', sendKeys);
app.post('/send/message', storeIncomingMessage);
app.post('/get/message', forwardMessageToClient);

const storageMap = {};
const messageStorageMap = {};

function receiveKeys(req, res){
    let reqObj = req.body;
    //console.log(req.body);
    let storageKey = reqObj.registrationId.toString() + reqObj.deviceId.toString();
    if(storageMap[storageKey]){
        res.json({err: 'Init packet for this user already exists'});
    } else {
        storageMap[storageKey] = reqObj;
        res.json({msg: 'Initial packet successfully saved'});
    }
    console.log('\n');
    console.log('storageMap~~~~~~~');
    console.log(storageMap);
}

function sendKeys(req, res){
    let reqObj = req.body;
    let storageKey = reqObj.registrationId.toString() + reqObj.deviceId.toString();
    let responseObject;
    if(storageMap[storageKey]){
        if(storageMap[storageKey].preKeys.length !== 0){
            responseObject = JSON.parse(JSON.stringify(storageMap[storageKey]));
            responseObject.preKey = responseObject.preKeys[responseObject.preKeys.length - 1];
            storageMap[storageKey].preKeys.pop();
        } else {
            responseObject = {err: 'Out of preKeys for this user'}
        }
    } else {
        responseObject = {
            err: 'Keys for ' + storageKey + ' user does not exist'
        }
    }
    console.log(responseObject);
    res.json(responseObject);
}

function storeIncomingMessage(req, res) {
    let reqObj = req.body;
    let messageStorageKey = reqObj.messageTo.registrationId.toString() + reqObj.messageTo.deviceId.toString() + reqObj.messageFrom.registrationId.toString() + reqObj.messageFrom.deviceId.toString();
    if(messageStorageMap[messageStorageKey]) {
        res.json({err: 'Can only deal with one message'});
    } else {
        messageStorageMap[messageStorageKey] = reqObj;
        res.json({msg: 'Message successfully saved'});
    }
    console.log('\n');
    console.log('~~~~~~~messageStorageMap~~~~~~~');
    console.log(messageStorageMap);
}

function forwardMessageToClient(req, res) {
    let reqObj = req.body;
    let messageStorageKey = reqObj.messageTo.registrationId.toString() + reqObj.messageTo.deviceId.toString() + reqObj.messageFromUniqueId;
    let responseObject;
    if(messageStorageMap[messageStorageKey]){
        if(storageMap[reqObj.messageFromUniqueId]){
            responseObject = messageStorageMap[messageStorageKey];
            responseObject.messageFrom = {
                registrationId: storageMap[reqObj.messageFromUniqueId].registrationId,
                deviceId: storageMap[reqObj.messageFromUniqueId].deviceId
            };
        } else {
            { err: 'Client: ' + reqObj.messageFromUniqueId + ' is not registered on this server.' }
        }
    } else {
        responseObject = { err: 'Message from: ' + reqObj.messageFromUniqueId + ' to: ' + reqObj.messageTo.registrationId.toString() + reqObj.messageTo.deviceId.toString() + ' does not exist' };
    }
    res.json(responseObject);
}