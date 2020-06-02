; ( () => {

    const genRandomStr = () => {
        return toHexString(window.crypto.getRandomValues(new Uint32Array(10)));
    }

    const utf8_to_b64 = (str) => {
        return window.btoa(unescape(encodeURIComponent(str)));
    }

    const b64_to_utf8 = (str) => {
        return decodeURIComponent(escape(window.atob(str)));
    }

    const toHexString = (byteArray) => {
        return Array.prototype.map.call(byteArray, (byte) => {
            return ('0' + (byte & 0xFF).toString(16)).slice(-2);
        }).join('');
    }

    const toByteArray = (hexString) => {
        const result = [];
        for (let i = 0; i < hexString.length; i += 2) {
            result.push(parseInt(hexString.substr(i, 2), 16));
        }
        return result;
    }

    const KeyHelper = libsignal.KeyHelper;

    const generateIdentity = (store) => {
        return Promise.all([
            KeyHelper.generateIdentityKeyPair(),
            KeyHelper.generateRegistrationId(),
        ]).then((result) => {
            store.put('identityKey', result[0]);
            store.put('registrationId', result[1]);
        });
    }

    const generatePreKeyBundle = (store, preKeyId, signedPreKeyId) => {
        return Promise.all([
            store.getIdentityKeyPair(),
            store.getLocalRegistrationId()
        ]).then((result) => {
            const identity = result[0];
            const registrationId = result[1];

            return Promise.all([
                KeyHelper.generatePreKey(preKeyId),
                KeyHelper.generateSignedPreKey(identity, signedPreKeyId),
            ]).then((keys) => {
                const preKey = keys[0]
                const signedPreKey = keys[1];

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

    const signalInit = (addr) => {
        const bobStore = new libsignal.SignalProtocolStore();
        const bobPreKeyId = 1;
        const bobSignedKeyId = 1;
        //const bobPreKeyId = parseInt(addr.charCodeAt(0).toString() + addr.charCodeAt(1).toString(), 10);
        //const bobSignedKeyId = parseInt(addr.charCodeAt(0).toString() + addr.charCodeAt(1).toString(), 10);
        return generateIdentity(bobStore).then( () => {
            return Promise.all([
                generatePreKeyBundle(bobStore, bobPreKeyId, bobSignedKeyId),
                Promise.resolve(bobStore)
            ]);
        });
    }

    const startSignalSessionWith = (addr) => {
        //const ALICE_KID = parseInt(addr.charCodeAt(0).toString() + addr.charCodeAt(1).toString(), 10);
        const ALICE_KID = 1;
        const ALICE_ADDRESS = new libsignal.SignalProtocolAddress(addr, ALICE_KID);
        const builder = new libsignal.SessionBuilder(window.nkt.signalStore, ALICE_ADDRESS);
        const preKeyBundle = window.nkt.userList[addr].preKey;
        const bobStore = window.nkt.signalStore;
        console.log('starting signal session with ' + addr);
        if (!window.nkt.userList[addr]) return;
        if (window.nkt.userList[addr].gotOk) return;
        return builder.processPreKey(preKeyBundle).then(((addr)=> () => {
            //console.log('HERE');
            //if (window.nkt.userList[addr].sessionEstablished) return;
            const originalMessage = utf8_to_b64(addr); // for double check on arrival
            const bobSessionCipher = new libsignal.SessionCipher(bobStore, ALICE_ADDRESS);
            //window.nkt.userList[addr].sessionCipher = bobSessionCipher;
            bobSessionCipher.encrypt(originalMessage).then((ciphertext) => {
                //console.log('ciphertext');
                //console.log(ciphertext);
                window.nkt.userList[addr].sessionCipher = bobSessionCipher;
                //window.nkt.userList[addr].keepSendingSessionEstablishment = setInterval(()=> {
                console.log('sending establishment');
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
        })(addr)).catch( (err) => { console.log('ERROR IN startsignalsession'); console.log(err); });
    }

    const decryptPreKeyMessageFrom = (message, from) => {
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

    const decryptMessageFrom = (message, from) => {
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

    const encryptMessageTo = (message, to) => {
        // console.log('encrypting for ' + to);
        const bobSessionCipher = window.nkt.userList[to].sessionCipher;
        if (!bobSessionCipher) {
            return Promise.reject('no session yet');
        }
        return bobSessionCipher.encrypt(utf8_to_b64(message));
    }

    // BUGOUT SERVER
    const startWebRTCServer = () => {
        const b = new Bugout(window.nkt.singleSwarmID, { "announce": window.nkt.trackers });
        b.heartbeat(2000);
        b.on('message', (address, message) => {
            handleMessageFromSwarm(address, message);
        });
        b.on('seen', (addr)=>{
            console.log('RTC SEEN');
            console.log(addr);
            window.dispatchEvent(new CustomEvent('nktwebrtcseen', { detail: addr }));
        });
        b.on('left', (addr)=>{
            console.log('RTC LEFT');
            console.log(addr);
            window.dispatchEvent(new CustomEvent('nktwebrtcleft', { detail: addr }));
        });
        return b;
    }

    // BUGOUT CLIENT
    const startWebRTCClient = (addr) => {
        /*
        const b = new Bugout(addr, { "announce": window.nkt.trackers });
        // Successfully joined user's swarm
        b.on('server', (address) => {
            console.log('swarm ' + addr + ' joined');
            window.nkt.userList[addr].swarmClient = b;
        });
        // Retry after some time in case of failure
        setTimeout( () => {
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
        */
    }

    const handlePingFromWebSocket = (message) => {
        if (Object(message) === message) {
            const swarmAddr = message.msgFrom;
            switch (message.msgType) {
                case 'newSwarmAddress':
                    if (!window.nkt.userList[swarmAddr]) {
                        handleUnknownSwarmAddress(swarmAddr);
                    }
                    break;
                default:
                    if (!window.nkt.userList[swarmAddr]) {
                        handleUnknownSwarmAddress(swarmAddr);
                    }
                    checkNotAlreadyIn(message, 'receivedMessages')
                        .then( () => {
                            message.fromChannel = 'websocket';
                            handleNewMessageReceived(message);
                        })
                        .catch( () => {
                            //console.log('already received');
                            //do nothing
                        })
                    break;
            }
        }
    }

    const handleUnknownSwarmAddress = (swarmAddr) => {
        if (swarmAddr === window.nkt.mySwarm.address()) return;
        window.nkt.userList[swarmAddr] = {};
        window.dispatchEvent(new CustomEvent('nktnewpeer', {
            detail: { data: { addr: swarmAddr } }
        }));
        console.log('joining new swarm ' + swarmAddr);
        startWebRTCClient(swarmAddr);
    }

    const beginSwarmAddrBroadcast = () => {
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

    const stopSwarmAddrBroadcast = () => {
        window.broadcastingSwarmAddr = true
    }

    const setClientAddressForSwarmPeer = (userId, addr) => {
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

    const handleMessageFromSwarm = (address, message) => {
        //console.log('RECEIVED MESSAGE FROM SWARM');
        //console.log(message);
        if (Object(message) === message && message.msgFrom) {
            setClientAddressForSwarmPeer(message.msgFrom, address);
        }
        checkNotAlreadyIn(message, 'receivedMessages')
            .then(() => {
                message.fromChannel = 'webrtc';
                if (message.msgType === 'newSwarmAddress') { // for me
                    if (!window.nkt.singleSwarmID) {
                        if (!window.nkt.userList[message.msgFrom].swarmClient) {
                            console.log('HEARING FROM SOMEONE IM NOT CONNECTED TO WEBRTC');
                            //startWebRTCClient(message.msgFrom);
                        }
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
            .catch( () => {
                //console.log('already received');
                //do nothing
            });
/*
        checkNotAlreadyIn(message, 'sentMessages')
            .then( () => {
                // broadcast to my swarm
                let userList = window.nkt.userList;
                if (window.nkt.singleSwarmID && false) window.nkt.mySwarm.send(message); // maybe unnecessary, avoid double sending
                for (let i in userList) {
                    if (userList[i].isUnreachable) continue;
                    if (userList[i].swarmAddress && !window.nkt.singleSwarmID) {
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
                   /*

                }

            }).catch(() => { })
            */
    }

    const resilientSend = (msgObj, encryptedBool, msgTo) => {
        if (Object(msgObj) === msgObj) msgObj.uid = msgObj.uid || genRandomStr();
        checkNotAlreadyIn(msgObj, 'sentMessages')
            .then( () => {
                //send through websocket,
                //loop for userList,  if swarmClient send also with webrtc
                const userList = window.nkt.userList;
                if (encryptedBool) {
                    for (let i in userList) {
                        if (userList[i].dontSendTo || userList[i].isUnreachable) continue; // TODO
                        if (msgTo && i !== msgTo) continue; // meh
                        encryptMessageTo(JSON.stringify(msgObj), i).then((ciphertext) => {
                            const msg = {
                                msgType: 'encrypted',
                                msgData: ciphertext.body,
                                msgTo: i,
                                msgFrom: window.nkt.mySwarm.address(),
                                uid: genRandomStr()
                            };
                            window.nkt.websocket.emit(window.nkt.websocketEventName, msg);
                            if (userList[i].swarmClient) userList[i].swarmClient.send(msg);
                            //if (window.nkt.singleSwarmID) window.nkt.mySwarm.send(userList[i].swarmAddress, msg);
                            if (window.nkt.singleSwarmID) window.nkt.mySwarm.send(msg);
                        }).catch((err) => {
                            if (window.nkt.userList[i].sessionCipher) {
                                console.log('error sending encrypted msg');
                                console.log(err);
                            }
                        });
                    }
                } else {
                    window.nkt.websocket.emit(window.nkt.websocketEventName, msgObj);
                    if (window.nkt.singleSwarmID) window.nkt.mySwarm.send(msgObj);
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
            .catch( (err) => {
                if (err) {
                    console.error(err);
                }
                //console.log('already sent');
                // do nothing
            });
    }

    const checkNotAlreadyIn = (msgObj, arrayName) => {
        if (
            (Object(msgObj) === msgObj
            && window.nkt[arrayName].indexOf(msgObj.uid) === -1)
            || !msgObj.uid
        ) {
            addToMessageArray(msgObj.uid, arrayName);
            if (!msgObj.uid) {
                console.log(arrayName + ' NO UID IN');
                console.log(msgObj);
            }
            return Promise.resolve();
        }
        return Promise.reject();
        /*
        return hashMessageObject(msgObj).then( (hashBuffer) => {
            let const = toHexString(new Uint8Array(hashBuffer));
            //console.log('checking not already in')
            //console.log(str);
            if (window.nkt[arrayName].indexOf(str) === -1) {
                addToMessageArray(str, arrayName);
                return Promise.resolve();
            }
            return Promise.reject();
        });
        */
    }

    const hashMessageObject = (msgObj) => {
        const buffer = new TextEncoder("utf-8").encode(JSON.stringify(msgObj));
        return crypto.subtle.digest("SHA-256", buffer);
    }

    const addToMessageArray = (msgHash, arrayName) => {
        if (window.nkt[arrayName].length > 1000) {
            window.nkt[arrayName].shift();
        }
        window.nkt[arrayName].push(msgHash);
    }

    const handleNewMessageReceived = (data) => {
        //console.log('GENERIC MESSAGE : ');
        //console.log(data);
        if (Object(data) === data && data.msgFrom) window.nkt.userList[data.msgFrom].isUnreachable = false;
        window.dispatchEvent(new CustomEvent('nktincomingdata', {
            detail: { data }
        }));
    }

    const startAskingForPreKey = (forAddr) => {
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

    const preKeyBundleToString = (bundle) => {
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

    const stringToPreKeyBundle = (string) => {
        const bundle = JSON.parse(string);
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

    const answerPreKeyRequest = (fromAddr, forAddr) => {
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

    const savePreKeyAnswer = (e) => {
        const preKey = stringToPreKeyBundle(e.detail.data.msgData);
        const addr = e.detail.data.msgFrom;
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

    const parseSessionEstablishment = (detail) => {
        const cipherType = detail.data.msgCipherType;
        if (cipherType === 3) {
            return decryptPreKeyMessageFrom(detail.data.msgData, detail.data.msgFrom);
        }
        return decryptMessageFrom(detail.data.msgData, detail.data.msgFrom);
    }

    const sendEncryptedMessage = (str, msgTo) => { // msgTo optional, private message
        const cont = window.dispatchEvent(new CustomEvent('nktsendingmessage', { detail: str }));
        if (!cont) return;
        resilientSend({
            msgType: 'humanMessage',
            msgData: str,
            msgDate: (new Date()).getTime().toString(),
            msgFrom: window.nkt.mySwarm.address()
        }, true, msgTo);
    }

    const sendClearMessage = (str) => {
        resilientSend({
            msgType: 'humanMessage',
            msgData: str,
            msgDate: (new Date()).getTime().toString(),
            msgFrom: window.nkt.mySwarm.address()
        }, false);
    }

    const setDebugListeners = () => {
        document.getElementById('submit').addEventListener('click',  (e) => {
            sendEncryptedMessage(document.getElementById('message').value);
        });
        window.addEventListener('nktnewpeer', (e) => {
            const addr = e.detail.data.addr;
            if (window.nkt.userList[addr] && window.nkt.userList[addr].wasShown) return;
            const pre = document.createElement('pre');
            pre.textContent = 'someone joined';
            document.getElementById('chat').appendChild(pre);
            window.nkt.userList[addr].wasShown = true;
        });
        window.nkt.plugin({
            name: 'displayMessage',
            listeners: {
                nktencryptedmessagereceived: (event) => {
                    const cont = window.dispatchEvent(new CustomEvent('nktdisplaymessage', { detail: event.detail }));
                    if (!cont) return;
                    const pre = document.createElement('pre');
                    pre.textContent = event.detail;
                    document.getElementById('chat').appendChild(pre);
                },
                nktsendingmessage: (event) => {
                    console.log('sending ' + event.detail)
                }
            }
        });
    }

    const askPeerToReEstablishSession = (addr) => {
        resilientSend({
            msgType: 'sessionEstablishmentOrder',
            msgData: 'ping',
            msgDate: (new Date()).getTime().toString(),
            msgFrom: window.nkt.mySwarm.address(),
            msgTo: addr
        }, false);
    }

    const setListeners = () => {
        window.addEventListener('nktincomingdata', (e) => {
            if (
                !e.detail.data.msgData
                || !e.detail.data.msgType
                || !e.detail.data.msgFrom
            ) return;
            if (e.detail.data.msgType === 'encrypted') return;
            try {
                const msg = e.detail.data;
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
                || e.detail.data.msgTo === e.detail.data.msgFrom
            ) return;
            decryptMessageFrom(e.detail.data.msgData, e.detail.data.msgFrom).then((plaintext) => {
                try {
                    const msg = JSON.parse(plaintext);
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
                const detail = JSON.parse(JSON.stringify(e.detail));
                (detail => {
                parseSessionEstablishment(detail).then((plaintext) => {
                    console.log('decrypted session establishment :');
                    console.log(plaintext);
                    if (plaintext === window.nkt.mySwarm.address()) {
                        window.nkt.userList[detail.data.msgFrom].sessionEstablished = true;
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
                        console.log(detail);
                        window.nkt.userList[detail.data.msgFrom].pauseSessionEstablishmentParsing = false;
                        if (!window.nkt.userList[detail.data.msgFrom].sessionEstablished) {
                            //delete window.nkt.userList[e.detail.data.msgFrom];
                            console.log('asking '+ detail.data.msgFrom +' to reestablish session')
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
                })(detail);
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

    const initPluginManager = () => {
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

    ; ( () => {
        window.nkt = {};
        window.nkt.singleSwarmID = "nktRYLi0Sn7BEQSPfo3KOiewur1gec";
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
        signalInit(window.nkt.mySwarm.address()).then((arr) => {
            let preKeyBundle = arr[0];
            let store = arr[1];
            window.nkt.signalStore = store;
            window.nkt.preKeyBundle = preKeyBundle;
            beginSwarmAddrBroadcast();
        });
        window.nkt.websocket.on(window.nkt.websocketEventName, handlePingFromWebSocket);
        window.nkt.sendEncryptedMessage = sendEncryptedMessage;
        window.nkt.sendClearMessage = sendClearMessage;
        setListeners();
        window.nkt.plugin = initPluginManager();

        // setDebugListeners();

    })();
})();