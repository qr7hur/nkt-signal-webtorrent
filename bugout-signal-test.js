
function utf8_to_b64( str ) {
return window.btoa(unescape(encodeURIComponent( str )));
}

function b64_to_utf8( str ) {
return decodeURIComponent(escape(window.atob( str )));
}

function toHexString(byteArray) {
    return Array.prototype.map.call(byteArray, function(byte) {
        return ('0' + (byte & 0xFF).toString(16)).slice(-2);
    }).join('');
}
function toByteArray(hexString) {
    var result = [];
    for (var i = 0; i < hexString.length; i += 2) {
        result.push(parseInt(hexString.substr(i, 2), 16));
    }
    return result;
}


var KeyHelper = libsignal.KeyHelper;

function generateIdentity(store) {
    return Promise.all([
        KeyHelper.generateIdentityKeyPair(),
        KeyHelper.generateRegistrationId(),
    ]).then(function(result) {
        store.put('identityKey', result[0]);
        store.put('registrationId', result[1]);
    });
}

function generatePreKeyBundle(store, preKeyId, signedPreKeyId) {
    return Promise.all([
        store.getIdentityKeyPair(),
        store.getLocalRegistrationId()
    ]).then(function(result) {
        var identity = result[0];
        var registrationId = result[1];

        return Promise.all([
            KeyHelper.generatePreKey(preKeyId),
            KeyHelper.generateSignedPreKey(identity, signedPreKeyId),
        ]).then(function(keys) {
            var preKey = keys[0]
            var signedPreKey = keys[1];

            store.storePreKey(preKeyId, preKey.keyPair);
            store.storeSignedPreKey(signedPreKeyId, signedPreKey.keyPair);

            return {
                identityKey: identity.pubKey,
                registrationId : registrationId,
                preKey:  {
                    keyId     : preKeyId,
                    publicKey : preKey.keyPair.pubKey
                },
                signedPreKey: {
                    keyId     : signedPreKeyId,
                    publicKey : signedPreKey.keyPair.pubKey,
                    signature : signedPreKey.signature
                }
            };
        });
    });
}



function signalInit(addr) {
    var BOB_ADDRESS   = new libsignal.SignalProtocolAddress(addr, 1);
    var bobStore = new libsignal.SignalProtocolStore();
    var bobPreKeyId = 1337;
    var bobSignedKeyId = 1;
    return generateIdentity(bobStore).then(function() {
        return Promise.all([
            generatePreKeyBundle(bobStore, bobPreKeyId, bobSignedKeyId),
            Promise.resolve(bobStore)
        ]);
    });
}

function startSignalSessionWith(addr) {
    var ALICE_ADDRESS = new libsignal.SignalProtocolAddress(addr, 1);
    var BOB_ADDRESS   = new libsignal.SignalProtocolAddress(window.nkt.mySwarm.address(), 1);
    var builder = new libsignal.SessionBuilder(window.nkt.signalStore, ALICE_ADDRESS);
    var preKeyBundle = window.nkt.userList[addr].preKey;
    var bobStore = window.nkt.signalStore;
    console.log('starting signal session with ' + addr);
    return builder.processPreKey(preKeyBundle).then(function() {
        var originalMessage = utf8_to_b64(addr); // for double check on arrival
        var bobSessionCipher = new libsignal.SessionCipher(bobStore, ALICE_ADDRESS);
        window.nkt.userList[addr].sessionCipher = bobSessionCipher;
        bobSessionCipher.encrypt(originalMessage).then((ciphertext) => {
            console.log('ciphertext');
            console.log(ciphertext);
            resilientSend({
                msgType: 'sessionEstablishment',
                msgData: ciphertext.body,
                msgCipherType: ciphertext.type,
                msgDate: (new Date()).getTime().toString(),
                msgFrom: window.nkt.mySwarm.address(),
                msgTo: addr
            });
        }).catch((err) => {console.log('encrypt err');console.log(err);});
        window.nkt.userList[addr].sessionEstablishing = setInterval(() => {
            /*
            if (window.nkt.userList[addr].sessionEstablished) return;
            bobSessionCipher.encrypt(originalMessage).then((ciphertext) => {
                console.log('ciphertext');
                console.log(ciphertext);
                resilientSend({
                    msgType: 'sessionEstablishment',
                    msgData: ciphertext.body,
                    msgCipherType: ciphertext.type,
                    msgDate: (new Date()).getTime().toString(),
                    msgFrom: window.nkt.mySwarm.address(),
                    msgTo: addr
                });
            });*/
        }, 20000);
    }).catch(function(err){console.log('ERROR IN startsignalsession');console.log(err);});
}

function decryptPreKeyMessageFrom(message, from) {
    return (
        window.nkt.userList[from].sessionCipher
        .decryptPreKeyWhisperMessage(message, 'binary')
        .then(plaintext => Promise.resolve(b64_to_utf8(signalUtil.toString(plaintext))))
        .catch(err => {console.log('decryptPreKeyMessageError');console.log(err)})
    );
}

function decryptMessageFrom(message, from) {
    return (
        window.nkt.userList[from].sessionCipher
        .decryptWhisperMessage(message, 'binary')
        .then(plaintext => Promise.resolve(b64_to_utf8(signalUtil.toString(plaintext))))
        .catch(err => {console.log('decryptMessageError');console.log(err)})
    );
}

function encryptMessageTo(message, to) {
    // console.log('encrypting for ' + to);
    var bobSessionCipher = window.nkt.userList[to].sessionCipher;
    if (!bobSessionCipher) {
        return Promise.reject('no session yet');
    }
    return bobSessionCipher.encrypt(utf8_to_b64(message));
}

/*

var alice_id = utf8_to_b64(window.crypto.getRandomValues(new Uint8Array(10)));
var bob_id = utf8_to_b64(window.crypto.getRandomValues(new Uint8Array(10)));
var ALICE_ADDRESS = new libsignal.SignalProtocolAddress(alice_id, 1);
var BOB_ADDRESS   = new libsignal.SignalProtocolAddress(bob_id, 1);

var aliceStore = new libsignal.SignalProtocolStore();
//var aliceStore = new SignalProtocolStore();

var bobStore = new libsignal.SignalProtocolStore();
//var bobStore = new SignalProtocolStore();

var bobPreKeyId = 1337;
var bobSignedKeyId = 1;

//var Curve = libsignal.Curve;

Promise.all([
    generateIdentity(aliceStore),
    generateIdentity(bobStore),
]).then(function() {
    return generatePreKeyBundle(bobStore, bobPreKeyId, bobSignedKeyId);
}).then(function(preKeyBundle) {
    // HERE BOB ADVERTISES HIS ADDRESS 
    var builder = new libsignal.SessionBuilder(aliceStore, BOB_ADDRESS);
    return builder.processPreKey(preKeyBundle).then(function() {

        //var originalMessage = util.toArrayBuffer("my message ......");
        var originalMessage = utf8_to_b64("test test");
        var aliceSessionCipher = new libsignal.SessionCipher(aliceStore, BOB_ADDRESS);
        var bobSessionCipher = new libsignal.SessionCipher(bobStore, ALICE_ADDRESS);

        aliceSessionCipher.encrypt(originalMessage).then(function(ciphertext) {

            // check for ciphertext.type to be 3 which includes the PREKEY_BUNDLE
            return bobSessionCipher.decryptPreKeyWhisperMessage(ciphertext.body, 'binary');

        }).then(function(plaintext) {

            bobSessionCipher.encrypt(originalMessage).then(function(ciphertext) {

            return aliceSessionCipher.decryptWhisperMessage(ciphertext.body, 'binary');

            }).then(function(plaintext) {

            console.log(b64_to_utf8(signalUtil.toString((plaintext))));
            console.log(b64_to_utf8(originalMessage));

            });

        });

    });
});


*/



// BUGOUT SERVER
function startWebRTCServer() {
    var b = new Bugout(undefined, {"announce": window.nkt.trackers});
    b.on('message', function(address, message) {
        handleMessageFromSwarm(address, message);
    });;
    return b;
}

// BUGOUT CLIENT
function startWebRTCClient(addr) {
    var b = new Bugout(addr, {"announce": window.nkt.trackers});
    // Successfully joined user's swarm
    b.on('server', function(address) {
        console.log('swarm ' + addr + ' joined');
        window.nkt.userList[addr].swarmClient = b;
    });
    // Retry after some time in case of failure
    setTimeout(function() {
        if (window.nkt.userList[addr] && !window.nkt.userList[addr].swarmClient) {
            window.nkt.userList[addr].swarmConnectionTrials = (
                window.nkt.userList[addr].swarmConnectionTrials
                ? window.nkt.userList[addr].swarmConnectionTrials + 1
                : 1
            );
            setTimeout(()=>{
                if (window.nkt.userList[b.serveraddress] && !window.nkt.userList[b.serveraddress].swarmClient) {
                    b.close()
                }
            }, 5000 * (window.nkt.userList[addr].swarmConnectionTrials || 1));
            //console.log('retry');
            startWebRTCClient(addr);
        }
    }, 5000);
}

function handlePingFromWebSocket(message) {
    if (Object(message) === message) {
        switch (message.msgType) {
            case 'newSwarmAddress':
                var swarmAddr = message.msgFrom;
                if (!window.nkt.userList[swarmAddr]) {
                    handleUnknownSwarmAddress(swarmAddr);
                }
                break;
            default:
                var swarmAddr = message.msgFrom;
                if (!window.nkt.userList[swarmAddr]) {
                    handleUnknownSwarmAddress(swarmAddr);
                }
                checkNotAlreadyIn(message, 'receivedMessages')
                .then(function() {
                    message.fromChannel = 'websocket';
                    handleNewMessageReceived(message);
                })
                .catch(function() {
                    //console.log('already received');
                    //do nothing
                })
                break;
        }
    }
}

function handleUnknownSwarmAddress(swarmAddr) {
    window.nkt.userList[swarmAddr] = {};
    window.dispatchEvent(new CustomEvent('nktnewpeer', {
        detail: { data: {addr: swarmAddr} }
    }));
    console.log('joining new swarm ' + swarmAddr);
    startWebRTCClient(swarmAddr);
}

function beginSwarmAddrBroadcast() {
    if (!window.broadcastingSwarmAddr) {
        window.broadcastingSwarmAddr = false;
        window.nkt.websocket.emit('nkt', {
            msgType: 'newSwarmAddress',
            msgFrom: window.nkt.mySwarm.address()
        });
        setTimeout(beginSwarmAddrBroadcast, 5000);
    }
}

function stopSwarmAddrBroadcast() {
    window.broadcastingSwarmAddr = true
}

function setClientAddressForSwarmPeer(userId, addr) {
    if (!window.nkt.userList[userId]) {
        window.nkt.userList[userId] = {};
    }
    if (window.nkt.userList[userId].swarmAddress === addr) {
        return;
    }
    window.nkt.userList[userId].swarmAddress = addr;
    window.dispatchEvent(new CustomEvent('nktnewpeer', {
        detail: { data: {addr: userId} }
    }));
}

function handleMessageFromSwarm(address, message) {
    if (Object(message) === message && message.msgFrom) {
        setClientAddressForSwarmPeer(message.msgFrom, address);
    }
    checkNotAlreadyIn(message, 'receivedMessages')
    .then(function() {
        message.fromChannel = 'webrtc';
        handleNewMessageReceived(message);
    })
    .catch(function() {
        //console.log('already received');
        //do nothing
    });

    checkNotAlreadyIn(message, 'sentMessages')
    .then(function() {
        // broadcast to my swarm
        var userList = window.nkt.userList;
        for (let i in userList) {
            if (userList[i].swarmAddress) {
                window.nkt.mySwarm.send(userList[i].swarmAddress, message);
            }
        }
    })
}

function resilientSend(msgObj, encryptedBool) {
    checkNotAlreadyIn(msgObj, 'sentMessages')
    .then(function() {
        window.dispatchEvent(new CustomEvent('nktoutgoingdata', {
            detail: { data: msgObj }
        }));
        //send through websocket,
        //loop for userList,  if swarmClient send also with webrtc
        var userList = window.nkt.userList;
        if (encryptedBool) {
            for (let i in userList) {
                encryptMessageTo(JSON.stringify(msgObj), i).then( (ciphertext) => {
                    var msg = {
                        msgType: 'encrypted',
                        msgData: ciphertext.body,
                        msgTo: i,
                        msgFrom: window.nkt.mySwarm.address()
                    };
                    window.nkt.websocket.emit('nkt', msg);
                    if (userList[i].swarmClient) userList[i].swarmClient.send(msg);
                }).catch((err)=> {
                    if (window.nkt.userList[i].sessionCipher) {
                        console.log('error sending encrypted msg');
                        console.log(err);
                    }
                });
            }
        } else {
            window.nkt.websocket.emit('nkt', msgObj);
            for (let i in userList) {
                if (userList[i].swarmClient) {
                    if (msgObj.msgTo) { // pour un destinataire
                        try {
                            userList[i].swarmClient.send(msgObj.msgTo, msgObj);
                        } catch(e) {console.log(e);}
                    } else { // sig, pour tout le monde
                        try {
                            userList[i].swarmClient.send(msgObj);
                        } catch(e) {console.log(e);}
                    }
                }
            }
        }
    })
    .catch(function(err) {
        if (err) {
            console.error(err);
        }
        //console.log('already sent');
        // do nothing
    });
}

function checkNotAlreadyIn(msgObj, arrayName) {
    return hashMessageObject(msgObj).then(function(hashBuffer) {
        var str = toHexString(new Uint8Array(hashBuffer));
        if (window.nkt[arrayName].indexOf(str) === -1) {
            addToMessageArray(str, arrayName);
            return Promise.resolve();
        }
        return Promise.reject();
    });
}

function hashMessageObject(msgObj) {
    var buffer = new TextEncoder("utf-8").encode(JSON.stringify(msgObj));
    return crypto.subtle.digest("SHA-256", buffer);
}

function addToMessageArray(msgHash, arrayName) {
    if (window.nkt[arrayName].length > 1000) {
        window.nkt[arrayName].shift();
    }
    window.nkt[arrayName].push(msgHash);
}

function handleNewMessageReceived(data) {
    //console.log('GENERIC MESSAGE : ');
    //console.log(data);
    window.dispatchEvent(new CustomEvent('nktincomingdata', {
        detail: { data }
    }));
}

function startAskingForPreKey(e) {
    console.log('asking for prekey ...');
    var forAddr = e.detail.data.addr;
    window.nkt.userList[forAddr].preKeyRequestCount = window.nkt.userList[forAddr].preKeyRequestCount || 0;
    window.nkt.userList[forAddr].preKeyRequestCount++;
    resilientSend({
        msgType: 'preKeyRequest',
        msgFrom: window.nkt.mySwarm.address(),
        msgForAddr: forAddr,
        msgTrial: window.nkt.userList[forAddr].preKeyRequestCount
    });
    //if (!window.nkt.userList[forAddr].preKey) {
    if (!window.nkt.userList[forAddr].sessionEstablished && !window.nkt.userList[forAddr].sessionEstablishing) {
        setTimeout(()=>startAskingForPreKey(e), 5000)
    }
}

function preKeyBundleToString(bundle) {
    return JSON.stringify({
        identityKey: toHexString(new Uint8Array(bundle.identityKey)),
        registrationId : bundle.registrationId,
        preKey:  {
            keyId     : bundle.preKey.keyId,
            publicKey : toHexString(new Uint8Array(bundle.preKey.publicKey))
        },
        signedPreKey: {
            keyId     : bundle.signedPreKey.keyId,
            publicKey : toHexString(new Uint8Array(bundle.signedPreKey.publicKey)),
            signature : toHexString(new Uint8Array(bundle.signedPreKey.signature))
        }
    });
}

function stringToPreKeyBundle(string) {
    var bundle = JSON.parse(string);
    return {
        identityKey: new Uint8Array(toByteArray(bundle.identityKey)).buffer,
        registrationId : bundle.registrationId,
        preKey:  {
            keyId     : bundle.preKey.keyId,
            publicKey : new Uint8Array(toByteArray(bundle.preKey.publicKey)).buffer
        },
        signedPreKey: {
            keyId     : bundle.signedPreKey.keyId,
            publicKey : new Uint8Array(toByteArray(bundle.signedPreKey.publicKey)).buffer,
            signature : new Uint8Array(toByteArray(bundle.signedPreKey.signature)).buffer
        }
    };
}

function answerPreKeyRequest(fromAddr) {
    resilientSend({
        msgType: 'preKey',
        msgData: preKeyBundleToString(window.nkt.preKeyBundle),
        msgDate: (new Date()).getTime().toString(),
        msgFrom: window.nkt.mySwarm.address(),
        msgTo: fromAddr
    });
}

function savePreKeyAnswer(e) {
    var preKey = stringToPreKeyBundle(e.detail.data.msgData);
    var addr = e.detail.data.msgFrom;
    //console.log('RECEIVED PREKEY');
    if (
        Object(window.nkt.userList[addr]) === window.nkt.userList[addr]
        && !window.nkt.userList[addr].sessionEstablished
        && !window.nkt.userList[addr].sessionEstablishing
        && !window.nkt.userList[addr].preKey
    ) {
        window.nkt.userList[addr].preKey = preKey;
        startSignalSessionWith(addr);
    }
}

function parseSessionEstablishment(e) {
    var cipherType = e.detail.data.msgCipherType;
    if (
        !window.nkt.userList[e.detail.data.msgFrom].sessionCipher
        || e.detail.data.msgTo !== window.nkt.mySwarm.address()
    ) {
        return Promise.reject();
    }
    if (cipherType === 3) {
        return decryptPreKeyMessageFrom(e.detail.data.msgData, e.detail.data.msgFrom);
    }
    return decryptMessageFrom(e.detail.data.msgData, e.detail.data.msgFrom);
}

function setListeners() {
    document.getElementById('submit').addEventListener('click', function(e) {
        resilientSend({
            msgType: 'humanMessage',
            msgData: document.getElementById('message').value,
            msgDate: (new Date()).getTime().toString(),
            msgFrom: window.nkt.mySwarm.address()
        }, true);
    });
    window.addEventListener('nktincomingdata', function(e) {
        if (
            !e.detail.data.msgData
            || !e.detail.data.msgType
            || !e.detail.data.msgTo
            || !e.detail.data.msgFrom
        ) return;
        if (
            e.detail.data.msgType !== 'encrypted'
            || e.detail.data.msgTo !== window.nkt.mySwarm.address()
        ) return;
        decryptMessageFrom(e.detail.data.msgData, e.detail.data.msgFrom).then( (plaintext) => {
            var msg = JSON.parse(plaintext);
            if (msg.msgType !== 'humanMessage') return;
            var pre = document.createElement('pre');
            pre.textContent = msg.msgData;
            document.getElementById('chat').appendChild(pre);
        }).catch(err => console.log(err))
    });

    // Signal
    window.addEventListener('nktnewpeer', function(e) {
        startAskingForPreKey(e);
    })
    window.addEventListener('nktincomingdata', function(e) {
        if (e.detail.data.msgType === 'preKeyRequest') {
            if (!e.detail.data.msgFrom) return;
            answerPreKeyRequest(e.detail.data.msgFrom);
        }
    });
    window.addEventListener('nktincomingdata', function(e) {
        if (e.detail.data.msgType === 'preKey') {
            savePreKeyAnswer(e);
        }
    });
    window.addEventListener('nktincomingdata', function(e) {
        if (e.detail.data.msgType === 'sessionEstablishment') {
            parseSessionEstablishment(e).then((plaintext) => {
                console.log('decrypted session establishment :');
                console.log(plaintext);
                if (plaintext === window.nkt.mySwarm.address()) {
                    window.nkt.userList[e.detail.data.msgFrom].sessionEstablished = true;
                    clearInterval(window.nkt.userList[e.detail.data.msgFrom].sessionEstablishing);
                    window.nkt.userList[e.detail.data.msgFrom].sessionEstablishing = false;
                    resilientSend({
                        msgType: 'pingMessage',
                        msgData: 'ping',
                        msgDate: (new Date()).getTime().toString(),
                        msgFrom: window.nkt.mySwarm.address()
                    }, true);
                }
            }).catch((err) => {
                clearInterval(window.nkt.userList[e.detail.data.msgFrom].sessionEstablishing);
                window.nkt.userList[e.detail.data.msgFrom].sessionEstablishing = false;
            });
        }
    });
}

;(function() {
    window.nkt = {}
    window.nkt.trackers = [
        "ws://localhost:8000",
        //"wss://hub.bugout.link",
        //"wss://tracker.openwebtorrent.com",
        //"wss://tracker.btorrent.xyz",
    ];
    window.nkt.userList = {};
    window.nkt.sentMessages = [];
    window.nkt.receivedMessages = [];
    window.nkt.websocket = io('http://localhost:3000');
    window.nkt.mySwarm = startWebRTCServer();
    signalInit(window.nkt.mySwarm.address()).then(function(arr) {
        var preKeyBundle = arr[0];
        var store = arr[1];
        window.nkt.signalStore = store;
        window.nkt.preKeyBundle = preKeyBundle;
        beginSwarmAddrBroadcast();
    });
    window.nkt.websocket.on('nkt', handlePingFromWebSocket);
    setListeners();
})();
