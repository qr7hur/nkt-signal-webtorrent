; (function () {

    function utf8_to_b64(str) {
        return window.btoa(unescape(encodeURIComponent(str)));
    }

    function b64_to_utf8(str) {
        return decodeURIComponent(escape(window.atob(str)));
    }

    function toHexString(byteArray) {
        return Array.prototype.map.call(byteArray, function (byte) {
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
        ]).then(function (result) {
            store.put('identityKey', result[0]);
            store.put('registrationId', result[1]);
        });
    }

    function generatePreKeyBundle(store, preKeyId, signedPreKeyId) {
        return Promise.all([
            store.getIdentityKeyPair(),
            store.getLocalRegistrationId()
        ]).then(function (result) {
            var identity = result[0];
            var registrationId = result[1];

            return Promise.all([
                KeyHelper.generatePreKey(preKeyId),
                KeyHelper.generateSignedPreKey(identity, signedPreKeyId),
            ]).then(function (keys) {
                var preKey = keys[0]
                var signedPreKey = keys[1];

                store.storePreKey(preKeyId, preKey.keyPair);
                store.storeSignedPreKey(signedPreKeyId, signedPreKey.keyPair);

                return {
                    identityKey: identity.pubKey,
                    registrationId: registrationId,
                    preKey: {
                        keyId: preKeyId,
                        publicKey: preKey.keyPair.pubKey
                    },
                    signedPreKey: {
                        keyId: signedPreKeyId,
                        publicKey: signedPreKey.keyPair.pubKey,
                        signature: signedPreKey.signature
                    }
                };
            });
        });
    }

    function signalInit(addr) {
        var bobStore = new libsignal.SignalProtocolStore();
        var bobPreKeyId = 1;
        var bobSignedKeyId = 1;
        //var bobPreKeyId = parseInt(addr.charCodeAt(0).toString() + addr.charCodeAt(1).toString(), 10);
        //var bobSignedKeyId = parseInt(addr.charCodeAt(0).toString() + addr.charCodeAt(1).toString(), 10);
        return generateIdentity(bobStore).then(function () {
            return Promise.all([
                generatePreKeyBundle(bobStore, bobPreKeyId, bobSignedKeyId),
                Promise.resolve(bobStore)
            ]);
        });
    }

    function startSignalSessionWith(addr) {
        //var ALICE_KID = parseInt(addr.charCodeAt(0).toString() + addr.charCodeAt(1).toString(), 10);
        var ALICE_KID = 1;
        var ALICE_ADDRESS = new libsignal.SignalProtocolAddress(addr, ALICE_KID);
        var builder = new libsignal.SessionBuilder(window.nkt.signalStore, ALICE_ADDRESS);
        var preKeyBundle = window.nkt.userList[addr].preKey;
        var bobStore = window.nkt.signalStore;
        console.log('starting signal session with ' + addr);
        if (!window.nkt.userList[addr]) return;
        if (window.nkt.userList[addr].gotOk) return;
        return builder.processPreKey(preKeyBundle).then(() => {
            console.log('HERE');
            //if (window.nkt.userList[addr].sessionEstablished) return;
            var originalMessage = utf8_to_b64(addr); // for double check on arrival
            var bobSessionCipher = new libsignal.SessionCipher(bobStore, ALICE_ADDRESS);
            //window.nkt.userList[addr].sessionCipher = bobSessionCipher;
            bobSessionCipher.encrypt(originalMessage).then((ciphertext) => {
                //console.log('ciphertext');
                //console.log(ciphertext);
                window.nkt.userList[addr].sessionCipher = bobSessionCipher;
                //window.nkt.userList[addr].keepSendingSessionEstablishment = setInterval(()=> {
                console.log('sending est');
                resilientSend({
                    msgType: 'sessionEstablishment',
                    msgData: ciphertext.body,
                    msgCipherType: ciphertext.type,
                    msgDate: (new Date()).getTime().toString(),
                    msgFrom: window.nkt.mySwarm.address(),
                    msgTo: addr
                });
                //}, 1000);
                //setTimeout(() => window.nkt.userList[addr].sessionError = false, 5000);
            }).catch((err) => { console.log('encrypt err'); console.log(err); });
        }).catch(function (err) { console.log('ERROR IN startsignalsession'); console.log(err); });
    }

    function decryptPreKeyMessageFrom(message, from) {
        return (
            window.nkt.userList[from].sessionCipher
                .decryptPreKeyWhisperMessage(message, 'binary')
                .then(plaintext => Promise.resolve(b64_to_utf8(signalUtil.toString(plaintext))))
                .catch(err => {
                    console.log('decryptPreKeyMessageError');
                    console.log(err);
                    //if (window.nkt.userList[from].sessionError) return;
                    
                    //if (window.nkt.userList[from].gotOk) return;
                    
                    console.log('trying to start new session');
                    //window.nkt.userList[from].sessionError = true;
                    //clearInterval(window.nkt.userList[from].keepSendingSessionEstablishment);
                    startSignalSessionWith(from);
                    
                })
        );
    }

    function decryptMessageFrom(message, from) {
        if (window.nkt.userList[from].sessionCipher) {
            return (
                window.nkt.userList[from].sessionCipher
                    .decryptWhisperMessage(message, 'binary')
                    .then(plaintext => Promise.resolve(b64_to_utf8(signalUtil.toString(plaintext))))
                    .catch(err => {
                        //console.log('decryptMessageError');
                        //console.log(err);
                        //if (window.nkt.userList[from].sessionError) return;
                        
                        //if (window.nkt.userList[from].gotOk) return;
                        /*
                        console.log('trying to start new session');
                        window.nkt.userList[from].sessionError = true;
                        clearInterval(window.nkt.userList[from].keepSendingSessionEstablishment);
                        startSignalSessionWith(from);
                        */
                    })
            );
        } else {
            return Promise.reject();
        }
    }

    function encryptMessageTo(message, to) {
        // console.log('encrypting for ' + to);
        var bobSessionCipher = window.nkt.userList[to].sessionCipher;
        if (!bobSessionCipher) {
            return Promise.reject('no session yet');
        }
        return bobSessionCipher.encrypt(utf8_to_b64(message));
    }

    // BUGOUT SERVER
    function startWebRTCServer() {
        var b = new Bugout(undefined, { "announce": window.nkt.trackers });
        b.on('message', function (address, message) {
            handleMessageFromSwarm(address, message);
        });;
        return b;
    }

    // BUGOUT CLIENT
    function startWebRTCClient(addr) {
        var b = new Bugout(addr, { "announce": window.nkt.trackers });
        // Successfully joined user's swarm
        b.on('server', function (address) {
            console.log('swarm ' + addr + ' joined');
            window.nkt.userList[addr].swarmClient = b;
        });
        // Retry after some time in case of failure
        setTimeout(function () {
            if (window.nkt.userList[addr] && !window.nkt.userList[addr].swarmClient) {
                window.nkt.userList[addr].swarmConnectionTrials = (
                    window.nkt.userList[addr].swarmConnectionTrials
                        ? window.nkt.userList[addr].swarmConnectionTrials + 1
                        : 1
                );
                setTimeout(() => {
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
                        .then(function () {
                            message.fromChannel = 'websocket';
                            handleNewMessageReceived(message);
                        })
                        .catch(function () {
                            //console.log('already received');
                            //do nothing
                        })
                    break;
            }
        }
    }

    function handleUnknownSwarmAddress(swarmAddr) {
        if (swarmAddr === window.nkt.mySwarm.address()) return;
        window.nkt.userList[swarmAddr] = {};
        window.dispatchEvent(new CustomEvent('nktnewpeer', {
            detail: { data: { addr: swarmAddr } }
        }));
        console.log('joining new swarm ' + swarmAddr);
        startWebRTCClient(swarmAddr);
    }

    function beginSwarmAddrBroadcast() {
        if (!window.broadcastingSwarmAddr) {
            window.broadcastingSwarmAddr = false;
            resilientSend({
                msgType: 'newSwarmAddress',
                msgFrom: window.nkt.mySwarm.address(),
                msgDate: (new Date()).getTime().toString()
            });
            /*
            window.nkt.websocket.emit(window.nkt.websocketEventName, {
                msgType: 'newSwarmAddress',
                msgFrom: window.nkt.mySwarm.address()
            });
            */
            setTimeout(beginSwarmAddrBroadcast, 5000);
        }
    }

    function stopSwarmAddrBroadcast() {
        window.broadcastingSwarmAddr = true
    }

    function setClientAddressForSwarmPeer(userId, addr) {
        if (userId === window.nkt.mySwarm.address()) return;
        if (!window.nkt.userList[userId]) {
            window.nkt.userList[userId] = {};
        }
        if (window.nkt.userList[userId].swarmAddress === addr) {
            return;
        }
        window.nkt.userList[userId].swarmAddress = addr;
        window.dispatchEvent(new CustomEvent('nktnewpeer', {
            detail: { data: { addr: userId } }
        }));
    }

    function handleMessageFromSwarm(address, message) {
        if (Object(message) === message && message.msgFrom) {
            setClientAddressForSwarmPeer(message.msgFrom, address);
        }
        checkNotAlreadyIn(message, 'receivedMessages')
            .then(function () {
                message.fromChannel = 'webrtc';
                if (message.msgType === 'newSwarmAddress') { // for me
                    if (!window.nkt.userList[message.msgFrom].swarmClient) {
                        console.log('HEARING FROM SOMEONE IM NOT CONNECTED TO WEBRTC');
                        //startWebRTCClient(message.msgFrom);
                    }
                    if (!window.nkt.userList[message.msgFrom].sessionEstablished) {
                        /*
                        console.log('HEARING FROM SOMEONE IM NOT CONNECTED TO SIGNAL');
                        startAskingForPreKey({
                            detail: { data: {addr: message.msgFrom} }
                        });*/
                    }
                }
                handleNewMessageReceived(message);
            })
            .catch(function () {
                //console.log('already received');
                //do nothing
            });

        checkNotAlreadyIn(message, 'sentMessages')
            .then(function () {
                // broadcast to my swarm
                var userList = window.nkt.userList;
                for (let i in userList) {
                    if (userList[i].isUnreachable) continue;
                    if (userList[i].swarmAddress) {
                        window.nkt.mySwarm.send(userList[i].swarmAddress, message);
                    }

                    /* // TODO use also swarmClients
                        if (
                            userList[i].swarmClient
                            && userList[i].sessionEstablished
                            && message.msgType === 'encrypted'
                        ) {
                            try {
                                userList[i].swarmClient.send(message);
                            } catch(e) {
                                // console.log(e);
                            }
                        }
                    */

                }

            }).catch(() => { })
    }

    function resilientSend(msgObj, encryptedBool, msgTo) {
        checkNotAlreadyIn(msgObj, 'sentMessages')
            .then(function () {
                //send through websocket,
                //loop for userList,  if swarmClient send also with webrtc
                var userList = window.nkt.userList;
                if (encryptedBool) {
                    for (let i in userList) {
                        if (userList[i].dontSendTo || userList[i].isUnreachable) continue; // TODO
                        if (msgTo && i !== msgTo) continue; // meh
                        encryptMessageTo(JSON.stringify(msgObj), i).then((ciphertext) => {
                            var msg = {
                                msgType: 'encrypted',
                                msgData: ciphertext.body,
                                msgTo: i,
                                msgFrom: window.nkt.mySwarm.address()
                            };
                            window.nkt.websocket.emit(window.nkt.websocketEventName, msg);
                            if (userList[i].swarmClient) userList[i].swarmClient.send(msg);
                        }).catch((err) => {
                            if (window.nkt.userList[i].sessionCipher) {
                                console.log('error sending encrypted msg');
                                console.log(err);
                            }
                        });
                    }
                } else {
                    window.nkt.websocket.emit(window.nkt.websocketEventName, msgObj);
                    for (let i in userList) {
                        if (userList[i].isUnreachable) continue;
                        if (userList[i].swarmClient) {
                            if (msgObj.msgTo && false) { // pour un destinataire //TODO utile ?
                                try {
                                    userList[i].swarmClient.send(msgObj.msgTo, msgObj);
                                } catch (e) { console.log(e); }
                            } else { // sig, pour tout le monde
                                try {
                                    userList[i].swarmClient.send(msgObj);
                                } catch (e) { console.log(e); }
                            }
                        }
                    }
                }
            })
            .catch(function (err) {
                if (err) {
                    console.error(err);
                }
                //console.log('already sent');
                // do nothing
            });
    }

    function checkNotAlreadyIn(msgObj, arrayName) {
        return hashMessageObject(msgObj).then(function (hashBuffer) {
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
        if (Object(data) === data && data.msgFrom) window.nkt.userList[data.msgFrom].isUnreachable = false;
        window.dispatchEvent(new CustomEvent('nktincomingdata', {
            detail: { data }
        }));
    }

    function startAskingForPreKey(forAddr) {
        if (
            !window.nkt.userList[forAddr]
            || window.nkt.userList[forAddr].receivedPreKey
        ) return;
        console.log('asking for ' + forAddr + '  prekey ...');
        window.nkt.userList[forAddr].preKeyRequestCount = window.nkt.userList[forAddr].preKeyRequestCount || 0;
        window.nkt.userList[forAddr].preKeyRequestCount++;
        resilientSend({
            msgType: 'preKeyRequest',
            msgFrom: window.nkt.mySwarm.address(),
            msgForAddr: forAddr,
            msgTrial: window.nkt.userList[forAddr].preKeyRequestCount
        });
        //setTimeout((function(forAddr){return function(){startAskingForPreKey(forAddr)}})(forAddr), 5000);
        setTimeout(() => startAskingForPreKey(forAddr), 5000);
        /*
        //if (!window.nkt.userList[forAddr].preKey) {
        if (!window.nkt.userList[forAddr].sessionEstablished) {
            setTimeout(() => startAskingForPreKey(forAddr), 5000)
        }
        */
    }

    function preKeyBundleToString(bundle) {
        return JSON.stringify({
            identityKey: toHexString(new Uint8Array(bundle.identityKey)),
            registrationId: bundle.registrationId,
            preKey: {
                keyId: bundle.preKey.keyId,
                publicKey: toHexString(new Uint8Array(bundle.preKey.publicKey))
            },
            signedPreKey: {
                keyId: bundle.signedPreKey.keyId,
                publicKey: toHexString(new Uint8Array(bundle.signedPreKey.publicKey)),
                signature: toHexString(new Uint8Array(bundle.signedPreKey.signature))
            }
        });
    }

    function stringToPreKeyBundle(string) {
        var bundle = JSON.parse(string);
        return {
            identityKey: new Uint8Array(toByteArray(bundle.identityKey)).buffer,
            registrationId: bundle.registrationId,
            preKey: {
                keyId: bundle.preKey.keyId,
                publicKey: new Uint8Array(toByteArray(bundle.preKey.publicKey)).buffer
            },
            signedPreKey: {
                keyId: bundle.signedPreKey.keyId,
                publicKey: new Uint8Array(toByteArray(bundle.signedPreKey.publicKey)).buffer,
                signature: new Uint8Array(toByteArray(bundle.signedPreKey.signature)).buffer
            }
        };
    }

    function answerPreKeyRequest(fromAddr, forAddr) {
        if (forAddr === window.nkt.mySwarm.address()) {//anwser for me
            resilientSend({
                msgType: 'preKey',
                msgData: preKeyBundleToString(window.nkt.preKeyBundle),
                msgDate: (new Date()).getTime().toString(),
                msgFrom: window.nkt.mySwarm.address(),
                msgTo: fromAddr
            });
        } else if(
            Object(window.nkt.userList[forAddr]) === window.nkt.userList[forAddr]
            && window.nkt.userList[forAddr].preKey
        ) {//answer for others if i know ?
            resilientSend({
                msgType: 'preKey',
                msgData: preKeyBundleToString(window.nkt.userList[forAddr].preKey),
                msgDate: (new Date()).getTime().toString(),
                msgFrom: forAddr,
                msgTo: fromAddr
            });
        }
    }

    function savePreKeyAnswer(e) {
        var preKey = stringToPreKeyBundle(e.detail.data.msgData);
        var addr = e.detail.data.msgFrom;
        //console.log('RECEIVED PREKEY');
        //console.log(preKey);
        //console.log(window.nkt.userList[addr]);
        //clearTimeout(window.nkt.userList[addr].askingForPreKeyTimeout);
        if (
            Object(window.nkt.userList[addr]) === window.nkt.userList[addr]
            && !window.nkt.userList[addr].receivedPreKey
        ) {
            window.nkt.userList[addr].receivedPreKey = true;
            window.nkt.userList[addr].preKey = preKey;
            startSignalSessionWith(addr);
        }
    }

    function parseSessionEstablishment(detail) {
        var cipherType = detail.data.msgCipherType;
        if (cipherType === 3) {
            return decryptPreKeyMessageFrom(detail.data.msgData, detail.data.msgFrom);
        }
        return decryptMessageFrom(detail.data.msgData, detail.data.msgFrom);
    }

    function sendEncryptedMessage(str, msgTo) { // msgTo optional, private message
        var cont = window.dispatchEvent(new CustomEvent('nktsendingmessage', { detail: str }));
        if (!cont) return;
        resilientSend({
            msgType: 'humanMessage',
            msgData: str,
            msgDate: (new Date()).getTime().toString(),
            msgFrom: window.nkt.mySwarm.address()
        }, true, msgTo);
    }

    function sendClearMessage(str) {
        resilientSend({
            msgType: 'humanMessage',
            msgData: str,
            msgDate: (new Date()).getTime().toString(),
            msgFrom: window.nkt.mySwarm.address()
        }, false);
    }

    function setDebugListeners() {
        document.getElementById('submit').addEventListener('click',  (e) => {
            sendEncryptedMessage(document.getElementById('message').value);
        });
        window.addEventListener('nktnewpeer', (e) => {
            var addr = e.detail.data.addr;
            if (window.nkt.userList[addr] && window.nkt.userList[addr].wasShown) return;
            var pre = document.createElement('pre');
            pre.textContent = 'someone joined';
            document.getElementById('chat').appendChild(pre);
            window.nkt.userList[addr].wasShown = true;
        });
        window.nkt.plugin({
            name: 'displayMessage',
            listeners: {
                nktencryptedmessagereceived: (event) => {
                    var cont = window.dispatchEvent(new CustomEvent('nktdisplaymessage', { detail: event.detail }));
                    if (!cont) return;
                    var pre = document.createElement('pre');
                    pre.textContent = event.detail;
                    document.getElementById('chat').appendChild(pre);
                },
                nktsendingmessage: (event) => {
                    console.log('sending ' + event.detail)
                }
            }
        });
    }

    function askPeerToReEstablishSession(addr) {
        resilientSend({
            msgType: 'sessionEstablishmentOrder',
            msgData: 'ping',
            msgDate: (new Date()).getTime().toString(),
            msgFrom: window.nkt.mySwarm.address(),
            msgTo: addr
        }, false);
    }

    function setListeners() {
        window.addEventListener('nktincomingdata', (e) => {
            if (
                !e.detail.data.msgData
                || !e.detail.data.msgType
                || !e.detail.data.msgFrom
            ) return;
            if (e.detail.data.msgType === 'encrypted') return;
            try {
                var msg = e.detail.data;
                if (msg.msgType !== 'humanMessage') return;
                window.dispatchEvent(new CustomEvent('nktclearmessagereceived', { detail: msg.msgData }));
            } catch (e) { }
        });
        window.addEventListener('nktincomingdata', (e) => {
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
            decryptMessageFrom(e.detail.data.msgData, e.detail.data.msgFrom).then((plaintext) => {
                try {
                    var msg = JSON.parse(plaintext);
                    if (msg.msgType !== 'humanMessage') return;
                    window.dispatchEvent(new CustomEvent('nktencryptedmessagereceived', { detail: msg.msgData }));
                } catch (e) { }
            }).catch(err => console.log(err))
        });

        // Signal
        window.addEventListener('nktnewpeer', (e) => {
            startAskingForPreKey(e.detail.data.addr);
        });
        window.addEventListener('nktincomingdata', (e) => {
            if (e.detail.data.msgType === 'preKeyRequest') {
                if (window.nkt.userList[e.detail.data.msgFrom].gotOk) return;
                if (!e.detail.data.msgFrom) return;
                answerPreKeyRequest(e.detail.data.msgFrom, e.detail.data.msgForAddr);
            }
        });
        window.addEventListener('nktincomingdata', (e) => {
            if (e.detail.data.msgType === 'preKey') {
                if (
                    window.nkt.userList[e.detail.data.msgFrom]
                    && window.nkt.userList[e.detail.data.msgFrom].gotOk
                ) return;
                savePreKeyAnswer(e);
            }
        });
        window.addEventListener('nktincomingdata', (e) => {
            if (e.detail.data.msgType === 'sessionEstablishment') {
                if (e.detail.data.msgTo !== window.nkt.mySwarm.address()) return;
                if (!window.nkt.userList[e.detail.data.msgFrom].sessionCipher) return;
                //if (window.nkt.userList[e.detail.data.msgFrom].gotOk) return;
                //if (window.nkt.userList[e.detail.data.msgFrom].pauseSessionEstablishmentParsing) return;
                window.nkt.userList[e.detail.data.msgFrom].pauseSessionEstablishmentParsing = true;
                console.log('PARSING SESSION ESTABLISHMENT FROM ' + e.detail.data.msgFrom);
                console.log(e.detail);
                parseSessionEstablishment(e.detail).then((plaintext) => {
                    console.log('decrypted session establishment :');
                    console.log(plaintext);
                    if (plaintext === window.nkt.mySwarm.address()) {
                        window.nkt.userList[e.detail.data.msgFrom].sessionEstablished = true;
                        resilientSend({
                            msgType: 'pingMessage',
                            msgData: 'encrypted test',
                            msgDate: (new Date()).getTime().toString(),
                            msgFrom: window.nkt.mySwarm.address()
                        }, true);
                        resilientSend({
                            msgType: 'sessionEstablishmentOk',
                            msgData: 'ping',
                            msgDate: (new Date()).getTime().toString(),
                            msgFrom: window.nkt.mySwarm.address(),
                            msgTo: e.detail.data.msgFrom
                        }, false);
                    } else {
                        console.log('BAD SESSION ESTABLISHMENT');
                        console.log(e);
                        window.nkt.userList[e.detail.data.msgFrom].pauseSessionEstablishmentParsing = false;
                        if (!window.nkt.userList[e.detail.data.msgFrom].sessionEstablished) {
                            //delete window.nkt.userList[e.detail.data.msgFrom];
                            console.log('asking '+ e.detail.data.msgFrom +' to reestablish session')
                            //askPeerToReEstablishSession(e.detail.data.msgFrom);
                            //console.log('prekey known for peer is');
                            //console.log(window.nkt.userList[e.detail.data.msgFrom].preKey);
                            //console.log('my prekey is');
                            //console.log(window.nkt.preKeyBundle);
                            //clearInterval(window.nkt.userList[e.detail.data.msgFrom].keepSendingSessionEstablishment);
                            //startSignalSessionWith(e.detail.data.msgFrom);
                            
                        }
                    }
                }).catch((err) => {
                    console.log('CANNOT DECRYPT SESSION ESTABLISHMENT');
                    console.log(err);
                    /*
                    window.nkt.userList[e.detail.data.msgFrom].pauseSessionEstablishmentParsing = false;
                    clearInterval(window.nkt.userList[e.detail.data.msgFrom].keepSendingSessionEstablishment);
                    startSignalSessionWith(e.detail.data.msgFrom);
                    */
                });
            }
        });
        window.addEventListener('nktincomingdata', (e) => {
            if (e.detail.data.msgType === 'sessionEstablishmentOrder' && false) { // nope (MAC ERROR)
                console.log('RECEIVED ORDER TO REESTABLISH');
                if (e.detail.data.msgTo !== window.nkt.mySwarm.address()) return;
                if (window.nkt.userList[e.detail.data.msgFrom].gotOk) return;
                clearInterval(window.nkt.userList[e.detail.data.msgFrom].keepSendingSessionEstablishment);
                startSignalSessionWith(e.detail.data.msgFrom);
            }
        });
        window.addEventListener('nktincomingdata', (e) => {
            if (e.detail.data.msgType === 'sessionEstablishmentOk') {
                if (e.detail.data.msgTo !== window.nkt.mySwarm.address()) return;
                if (window.nkt.userList[e.detail.data.msgFrom].gotOk) return;
                console.log('GOT OK FROM ' + e.detail.data.msgFrom);
                window.nkt.userList[e.detail.data.msgFrom].pauseSessionEstablishmentParsing = true;
                //clearInterval(window.nkt.userList[e.detail.data.msgFrom].keepSendingSessionEstablishment);
                window.nkt.userList[e.detail.data.msgFrom].gotOk = true;
            }
        });
    }

    function initPluginManager() {
        window.nkt.plugins = {};
        return (plugin) => {
            if (Object(plugin) !== plugin) {
                throw new Error('plugin is not an object');
            }
            if (!plugin.name) {
                throw new Error('plugin.name empty');
            }
            if (Object(plugin.listeners) !== plugin.listeners) {
                throw new Error('plugin.listeners must be an object');
            }
            window.nkt.plugins[plugin.name] = plugin;
            for (let event in plugin.listeners) {
                window.addEventListener(event, plugin.listeners[event]);
            }
        };
    }

    ; (function () {
        window.nkt = {};
        window.nkt.trackers = [
            "wss://hub.bugout.link",
            "wss://tracker.openwebtorrent.com",
            "wss://tracker.btorrent.xyz",
        ];
        window.nkt.userList = {};
        window.nkt.sentMessages = [];
        window.nkt.receivedMessages = [];
        if (window.location.href.indexOf('localhost') > -1) {
            window.nkt.trackers.push("ws://localhost:8000");
            window.nkt.websocket = io('http://localhost:3000');
            window.nkt.websocketEventName = 'nkt';
        } else {
            window.nkt.websocket = io("wss://" + window.location.hostname);
            window.nkt.websocketEventName = 'corev2';
        }
        window.nkt.mySwarm = startWebRTCServer();
        signalInit(window.nkt.mySwarm.address()).then(function (arr) {
            var preKeyBundle = arr[0];
            var store = arr[1];
            window.nkt.signalStore = store;
            window.nkt.preKeyBundle = preKeyBundle;
            beginSwarmAddrBroadcast();
        });
        window.nkt.websocket.on(window.nkt.websocketEventName, handlePingFromWebSocket);
        window.nkt.sendEncryptedMessage = sendEncryptedMessage;
        window.nkt.sendClearMessage = sendClearMessage;
        window.nkt.startWebRTCClient = startWebRTCClient; // for manual join without websocket
        setListeners();
        window.nkt.plugin = initPluginManager();

        // setDebugListeners();

    })();
})();