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
                store.put('_signature', signedPreKey.signature);

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

    const generateNewPreKeyBundle = (store, preKeyId, signedPreKeyId) => {
        return Promise.all([
            store.getIdentityKeyPair(),
            store.getLocalRegistrationId()
        ]).then((result) => {
            const identity = result[0];
            const registrationId = result[1];

            return Promise.all([
                KeyHelper.generatePreKey(preKeyId),
                //KeyHelper.generateSignedPreKey(identity, signedPreKeyId),
                store.loadSignedPreKey(signedPreKeyId)
            ]).then((keys) => {
                const preKey = keys[0]
                const signedPreKey = keys[1];

                store.storePreKey(preKeyId, preKey.keyPair);
                //store.storeSignedPreKey(signedPreKeyId, signedPreKey.keyPair);
                const signature = store.get('_signature');

                return {
                    identityKey: identity.pubKey,
                    registrationId: registrationId,
                    preKey: {
                        keyId: preKeyId,
                        publicKey: preKey.keyPair.pubKey
                    },
                    signedPreKey: {
                        keyId: signedPreKeyId,
                        publicKey: signedPreKey.pubKey,
                        signature: signature
                    }
                };
            });
        });
    }

    const signalInit = () => {
        const bobStore = new libsignal.SignalProtocolStore();
        const bobPreKeyId = 1;
        const bobSignedKeyId = 1;
        //const bobPreKeyId = parseInt(addr.charCodeAt(0).toString() + addr.charCodeAt(1).toString(), 10);
        //const bobSignedKeyId = parseInt(addr.charCodeAt(0).toString() + addr.charCodeAt(1).toString(), 10);
        if (!window.nkt.signalStore) {
            return generateIdentity(bobStore).then( () => {
                return Promise.all([
                    generatePreKeyBundle(bobStore, bobPreKeyId, bobSignedKeyId),
                    Promise.resolve(bobStore)
                ]);
            });
        }
    }

    const startSignalSessionWith = (addr) => {
        if (!window.nkt.userList[addr].receivedOrderToEstablish) return;
        // || window.nkt.userList[addr].tryingToStartSession) return;
        //window.nkt.userList[addr].tryingToStartSession = true;
        //if (window.nkt.userList[addr].waitingForPeerToEstablish) return;
        //const ALICE_KID = parseInt(addr.charCodeAt(0).toString() + addr.charCodeAt(1).toString(), 10);
        const ALICE_DEVICE_ID = 1;
        const ALICE_ADDRESS = new libsignal.SignalProtocolAddress(addr, ALICE_DEVICE_ID);
        const builder = new libsignal.SessionBuilder(window.nkt.signalStore, ALICE_ADDRESS);
        const preKeyBundle = window.nkt.userList[addr].preKey;
        const bobStore = window.nkt.signalStore;
        logIfVerbose('starting signal session with ' + addr);
        if (!window.nkt.userList[addr]) return;
        //if (window.nkt.userList[addr].gotOk) return;
        //window.nkt.signalStore.removeSession(addr + '.1');
        return builder.processPreKey(preKeyBundle).then(((addr)=> () => {
            //logIfVerbose('HERE');
            //if (window.nkt.userList[addr].sessionEstablished) return;
            const originalMessage = utf8_to_b64(addr); // for double check on arrival
            //const bobSessionCipher = new libsignal.SessionCipher(bobStore, ALICE_ADDRESS);
            //window.nkt.userList[addr].sessionCipher = bobSessionCipher;
            //window.nkt.userList[addr].sessionCipher = undefined;
            const ALICE_DEVICE_ID = 1;
            const ALICE_ADDRESS = new libsignal.SignalProtocolAddress(addr, ALICE_DEVICE_ID);
            window.nkt.userList[addr].sessionCipher = new libsignal.SessionCipher(bobStore, ALICE_ADDRESS);
            window.nkt.userList[addr].sessionCipher
            .encrypt(originalMessage)
            .then((ciphertext) => {
                //logIfVerbose('ciphertext');
                //logIfVerbose(ciphertext);
                //window.nkt.userList[addr].sessionCipher = bobSessionCipher;
                //window.nkt.userList[addr].keepSendingSessionEstablishment = setInterval(()=> {
                logIfVerbose('sending establishment');
                resilientSend({
                    msgType: 'sessionEstablishment',
                    msgData: ciphertext.body,
                    msgCipherType: ciphertext.type,
                    msgDate: (new Date()).getTime().toString(),
                    msgFrom: window.nkt.mySwarm.address(),
                    msgBugoutPk: window.nkt.mySwarm.pk,
                    msgBugoutEk: window.nkt.mySwarm.ek,
                    msgTo: addr
                });
                //window.nkt.userList[addr].receivedOrderToEstablish = false;
                //}, 1000);
                //setTimeout(() => window.nkt.userList[addr].sessionError = false, 5000);
            }).catch((err) => { logIfVerbose('encrypt err'); logIfVerbose(err); });
        })(addr)).catch( (err) => { logIfVerbose('ERROR IN startsignalsession'); logIfVerbose(err); });
    }

    const decryptPreKeyMessageFrom = (message, from) => {
        logIfVerbose('DECRYPTING');
        /*
        if (!window.nkt.userList[from].preKey) {
            // preKey not received yet
            logIfVerbose('waiting for key');
            setTimeout(((message, from)=>()=>decryptPreKeyMessageFrom(message, from))(), 200);
        }
        */
        const ALICE_DEVICE_ID = 1;
        const ALICE_ADDRESS = new libsignal.SignalProtocolAddress(from, ALICE_DEVICE_ID);
        const bobStore = window.nkt.signalStore; 
        const aliceSessionCipher = new libsignal.SessionCipher(bobStore, ALICE_ADDRESS);
        window.nkt.userList[from].sessionCipher = aliceSessionCipher;
        return (aliceSessionCipher
                .decryptPreKeyWhisperMessage(message, 'binary')
                .then(plaintext => Promise.resolve(b64_to_utf8(signalUtil.toString(plaintext))))
                .catch(err => {
                    logIfVerbose('decryptPreKeyWhisperMessage error');
                    logIfVerbose(err);
                    /*
                    if (
                        !window.nkt.userList[from].sessionEstablished
                        || window.nkt.userList[from].gotOk
                    ) return;
                    logIfVerbose('decryptPreKeyMessageError');
                    logIfVerbose(err);
                    */
                    //if (window.nkt.userList[from].sessionError) return;
                    
                    //if (window.nkt.userList[from].gotOk) return;
                    
                    //logIfVerbose('trying to start new session');
                    //window.nkt.userList[from].sessionError = true;
                    //clearInterval(window.nkt.userList[from].keepSendingSessionEstablishment);
                    // PISTE
                    //setTimeout((from=>()=>startSignalSessionWith(from))(from), 100);
                    //window.nkt.userList[from].tryingToStartSession = false;
                    //startSignalSessionWith(from);
                    
                })
        );
    }

    const decryptMessageFrom = (message, from, cipherType) => {
        if (cipherType === 3) {
            return decryptPreKeyMessageFrom(message, from);
        }
        if (window.nkt.userList[from].sessionCipher) {
            return (
                window.nkt.userList[from].sessionCipher
                    .decryptWhisperMessage(message, 'binary')
                    .then(plaintext => Promise.resolve(b64_to_utf8(signalUtil.toString(plaintext))))
                    .catch(err => {
                        logIfVerbose('decryptWhisperMessage error');
                        logIfVerbose(err);
                        //if (window.nkt.userList[from].sessionError) return;
                        
                        //if (window.nkt.userList[from].gotOk) return;
                        /*
                        logIfVerbose('trying to start new session');
                        window.nkt.userList[from].sessionError = true;
                        clearInterval(window.nkt.userList[from].keepSendingSessionEstablishment);
                        startSignalSessionWith(from);
                        
                        logIfVerbose('decryptMessageError');
                        logIfVerbose(err);
                        window.nkt.userList[from].tryingToStartSession = false;
                        startSignalSessionWith(from);
                        */
                    })
            );
        } else {
            logIfVerbose('received non prekey message but got no session yet');
            //startSignalSessionWith(from);
            return Promise.reject();
        }
    }

    const encryptMessageTo = (message, to) => {
        // logIfVerbose('encrypting for ' + to);
        const bobSessionCipher = window.nkt.userList[to].sessionCipher;
        if (!bobSessionCipher) {
            return Promise.reject('no session yet');
        }
        return bobSessionCipher.encrypt(utf8_to_b64(message));
    }

    // BUGOUT SERVER
    const startWebRTCServer = () => {
        const b = new Bugout(window.nkt.singleSwarmID, {
            "announce": window.nkt.trackers,
            "iceServers": window.nkt.iceServers
        });
        //b.heartbeat(2000);
        b.on('message', (address, message) => {
            handleMessageFromSwarm(address, message);
        });
        b.on('seen', (addr)=>{
            logIfVerbose('RTC SEEN');
            logIfVerbose(addr);
            window.dispatchEvent(new CustomEvent('nktwebrtcseen', { detail: addr }));
        });
        b.on('left', (addr)=>{
            logIfVerbose('RTC LEFT');
            logIfVerbose(addr);
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
            logIfVerbose('swarm ' + addr + ' joined');
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
                //logIfVerbose('retry');
                startWebRTCClient(addr);
            }
        }, 5000);
        */
    }

    const handlePingFromWebSocket = (message) => {
        if (Object(message) === message) {
            const swarmAddr = message.msgFrom;
            const bugoutPk = message.msgBugoutPk;
            const bugoutEk = message.msgBugoutEk;
            switch (message.msgType) {
                case 'newSwarmAddress':
                    //for (let addr of swarmAddr.split(',')) {
                        if (!window.nkt.userList[swarmAddr]) {
                            handleUnknownSwarmAddress(swarmAddr, bugoutPk, bugoutEk);
                        }
                    //}
                    break;
                default:
                    if (!window.nkt.userList[swarmAddr]) {
                        handleUnknownSwarmAddress(swarmAddr, bugoutPk, bugoutEk);
                    }
                    checkNotAlreadyIn(message, 'receivedMessages')
                        .then( () => {
                            if (
                                message.msgType === 'bugoutEncrypted'
                                && message.msgTo === window.nkt.mySwarm.address()
                            ) {
                                message = bugoutDecrypt(window.nkt.mySwarm, message.msgData);
                                if (!message) {
                                    logIfVerbose('bugout decrypt failed');
                                    return;
                                }
                            }
                            message.fromChannel = 'websocket';
                            handleNewMessageReceived(message);
                        })
                        .catch( () => {
                            //logIfVerbose('already received');
                            //do nothing
                        })
                    break;
            }
        }
    }

    const handleUnknownSwarmAddress = (swarmAddr, bugoutPk, bugoutEk) => {
        if (swarmAddr === window.nkt.mySwarm.address()) return;
        window.nkt.userList[swarmAddr] = {};
        if (!window.nkt.mySwarm.peers[swarmAddr]) {
            window.nkt.mySwarm.peers[swarmAddr] = {
                pk: bugoutPk,
                ek: bugoutEk,
                last: 0
            };
        }
        
        window.dispatchEvent(new CustomEvent('nktnewpeer', {
            detail: { data: { addr: swarmAddr } }
        }));
        //logIfVerbose('joining new swarm ' + swarmAddr);
        //startWebRTCClient(swarmAddr);
    }

    //const setClientAddressForSwarmPeer = (userId, addr, bugoutPk, bugoutEk) => {
    const setClientAddressForSwarmPeer = (addr, userId, bugoutPk, bugoutEk) => {
        if (userId === window.nkt.mySwarm.address()) return;
        if (!window.nkt.userList[userId]) {
            window.nkt.userList[userId] = {};
            if (!window.nkt.mySwarm.peers[userId]) {
                window.nkt.mySwarm.peers[userId] = {
                    pk: bugoutPk,
                    ek: bugoutEk,
                    last: 0
                };
            }
        }
        if (window.nkt.userList[userId].swarmAddress === addr) {
            return;
        }
        window.nkt.userList[userId].swarmAddress = addr;
        window.dispatchEvent(new CustomEvent('nktnewpeer', {
            detail: { data: { addr: userId } }
        }));
    }


    const beginSwarmAddrBroadcast = () => {
        if (!window.broadcastingSwarmAddr) {
            window.broadcastingSwarmAddr = false;
            // Broadcast known peers also !
            const addrArr = Object.keys(window.nkt.userList);
            //const userStr = (addrArr.length > 0) ? ',' + addrArr.join(',') : '';
            const userStr = ''; //DEBUG
            resilientSend({
                msgType: 'newSwarmAddress',
                msgFrom: window.nkt.mySwarm.address() + userStr,
                msgBugoutPk: window.nkt.mySwarm.pk,
                msgBugoutEk: window.nkt.mySwarm.ek,
                msgDate: (new Date()).getTime().toString()
            });

            /*
            // Broadcast known peers
            for (let i in window.nkt.userList) {
                resilientSend({
                    msgType: 'newSwarmAddress',
                    msgFrom: i,
                    msgDate: (new Date()).getTime().toString()
                });
            }
            */
            
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

    

    const handleMessageFromSwarm = (address, message) => {
        //logIfVerbose('RECEIVED MESSAGE FROM SWARM');
        //logIfVerbose(message);
        if (Object(message) === message && message.msgFrom) {
            setClientAddressForSwarmPeer(address, message.msgFrom, message.msgBugoutPk, message.msgBugoutEk);
        }
        checkNotAlreadyIn(message, 'receivedMessages')
            .then(() => {
                message.fromChannel = 'webrtc';
                if (message.msgType === 'newSwarmAddress') { // for me
                    if (!window.nkt.singleSwarmID) {
                        if (!window.nkt.userList[message.msgFrom].swarmClient) {
                            logIfVerbose('HEARING FROM SOMEONE IM NOT CONNECTED TO WEBRTC');
                            //startWebRTCClient(message.msgFrom);
                        }
                    }
                    if (!window.nkt.userList[message.msgFrom].sessionEstablished) {
                        /*
                        logIfVerbose('HEARING FROM SOMEONE IM NOT CONNECTED TO SIGNAL');
                        startAskingForPreKey({
                            detail: { data: {addr: message.msgFrom} }
                        });*/
                    }
                }
                handleNewMessageReceived(message);
            })
            .catch( () => {
                //logIfVerbose('already received');
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
                                // logIfVerbose(e);
                            }
                        }
                    */
                   /*

                }

            }).catch(() => { })
            */
    }

    function now() {
        return (new Date()).getTime();
    }

    function bugoutMakePacket(bugout, params) {
        var p = {
          "t": now(),
          "i": bugout.identifier,
          "pk": bugout.pk,
          "ek": bugout.ek,
          "n": nacl.randomBytes(8),
        };
        for (var k in params) {
          p[k] = params[k];
        }
        pe = bencode.encode(p);
        return bencode.encode({
          "s": nacl.sign.detached(pe, bugout.keyPair.secretKey),
          "p": pe,
        });
      }

    const bugoutEncrypt = (bugout, pk, packet) => {
        if (bugout.peers[bugout.address(pk)]) {
            var nonce = nacl.randomBytes(nacl.box.nonceLength);
            packet = bencode.encode({
            "n": nonce,
            "ek": bs58.encode(Buffer.from(bugout.keyPairEncrypt.publicKey)),
            "e": nacl.box(packet, nonce, bs58.decode(bugout.peers[bugout.address(pk)].ek), bugout.keyPairEncrypt.secretKey),
            });
        } else {
            throw bugout.address(pk) + " not seen - no encryption key.";
        }
        return packet;
    }

    const bugoutDecrypt = (bugout, message) => {
        var unpacked = bencode.decode(message);
        // if this is an encrypted packet first try to decrypt it
        if (unpacked.e && unpacked.n && unpacked.ek) {
            var ek = unpacked.ek.toString();
            //logIfVerbose("message encrypted by", ek, unpacked);
            var decrypted = nacl.box.open(unpacked.e, unpacked.n, bs58.decode(ek), bugout.keyPairEncrypt.secretKey);
            if (decrypted) {
                unpacked = bencode.decode(decrypted);
            } else {
                unpacked = null;
            }
        }
        // if there's no data decryption failed
        if (unpacked && unpacked.p) {
            //logIfVerbose("unpacked message", unpacked);
            var packet = bencode.decode(unpacked.p);
            var pk = packet.pk.toString();
            var id = packet.i.toString();
            var checksig = nacl.sign.detached.verify(unpacked.p, unpacked.s, bs58.decode(pk));
            var checkid = id == bugout.identifier;
            var checktime = true;
            //logIfVerbose("packet", packet);
            if (checksig && checkid && checktime) {
                // message is authenticated
                var ek = packet.ek.toString();
                // check packet types
                //logIfVerbose("message", bugout.identifier, packet);
                var messagestring = packet.v.toString();
                //logIfVerbose('MESSAGE STRING',messagestring)
                var messagejson = null;
                try {
                    var messagejson = JSON.parse(messagestring);
                } catch(e) {
                    logIfVerbose("Malformed message JSON: " + messagestring);
                }
                if (messagejson) {
                    return messagejson;
                }
            } else {
                logIfVerbose("dropping bad packet", checksig, checkid, checktime);
            }
        } else {
            logIfVerbose("skipping packet with no payload", unpacked);
        }
        // forward first-seen message to all connected wires
        // TODO: block flooders
        return {};
    }

    const resilientSend = (msgObj, encryptedBool, msgTo) => {
        if (Object(msgObj) === msgObj) msgObj.uid = msgObj.uid || genRandomStr();
        return checkNotAlreadyIn(msgObj, 'sentMessages')
            .then( () => {
                //logIfVerbose('RESILIENT SEND');
                //send through websocket,
                //loop for userList,  if swarmClient send also with webrtc
                const userList = window.nkt.userList;
                if (encryptedBool) {
                    for (let i in userList) {
                        if (userList[i].dontSendTo || userList[i].isUnreachable) continue; // TODO
                        if (msgTo && i !== msgTo) continue; // meh
                        if (!userList[i].useSignal) {
                            const msg = {
                                msgDate: msgObj.msgDate,
                                msgType: 'bugoutEncrypted',
                                msgData: msgObj.msgData,
                                msgTo: i,
                                msgFrom: window.nkt.mySwarm.address(), 
                                msgBugoutPk: window.nkt.mySwarm.pk,
                                msgBugoutEk: window.nkt.mySwarm.ek,
                                uid: genRandomStr()
                            };
                            if (window.nkt.singleSwarmID) window.nkt.mySwarm.send(i, msg);
                            window.nkt.websocket.emit(
                                window.nkt.websocketEventName,
                                {
                                    msgDate: msgObj.msgDate,
                                    msgType: 'bugoutEncrypted',
                                    msgData: bugoutEncrypt(
                                        window.nkt.mySwarm,
                                        window.nkt.mySwarm.peers[i].pk,
                                        bugoutMakePacket(window.nkt.mySwarm, {"y":"m","v": JSON.stringify(msg)})
                                    ),
                                    msgTo: i,
                                    msgFrom: window.nkt.mySwarm.address(), 
                                    msgBugoutPk: window.nkt.mySwarm.pk,
                                    msgBugoutEk: window.nkt.mySwarm.ek,
                                    uid: msg.uid
                                }
                            );
                            
                            continue;
                        }
                        encryptMessageTo(JSON.stringify(msgObj), i).then((ciphertext) => {
                            const msg = {
                                msgType: 'encrypted',
                                msgData: ciphertext.body,
                                msgTo: i,
                                msgFrom: window.nkt.mySwarm.address(),
                                msgCipherType: ciphertext.type,
                                msgBugoutPk: window.nkt.mySwarm.pk,
                                msgBugoutEk: window.nkt.mySwarm.ek,
                                uid: genRandomStr()
                            };
                            window.nkt.websocket.emit(window.nkt.websocketEventName, msg);
                            if (userList[i].swarmClient) userList[i].swarmClient.send(msg);
                            //if (window.nkt.singleSwarmID) window.nkt.mySwarm.send(userList[i].swarmAddress, msg);
                            if (window.nkt.singleSwarmID) window.nkt.mySwarm.send(msg);
                        }).catch((err) => {
                            if (window.nkt.userList[i].sessionCipher) {
                                logIfVerbose('error sending encrypted msg');
                                logIfVerbose(err);
                            }
                        });
                    }
                } else {
                    window.nkt.websocket.emit(window.nkt.websocketEventName, msgObj);
                    if (window.nkt.singleSwarmID) window.nkt.mySwarm.send(msgObj);
                    else {
                        for (let i in userList) {
                            if (userList[i].isUnreachable) continue;
                            if (userList[i].swarmClient) {
                                if (msgObj.msgTo && false) { // pour un destinataire //TODO utile ?
                                    try {
                                        userList[i].swarmClient.send(msgObj.msgTo, msgObj);
                                    } catch (e) { logIfVerbose(e); }
                                } else { // sig, pour tout le monde
                                    try {
                                        userList[i].swarmClient.send(msgObj);
                                    } catch (e) { logIfVerbose(e); }
                                }
                            }
                        }
                    }
                }
            })
            .catch( (err) => {
                if (err) {
                    console.error(err);
                }
                //logIfVerbose('already sent');
                // do nothing
            });
    }

    const checkNotAlreadyIn = (msgObj, arrayName) => {
        if (
            (Object(msgObj) === msgObj
            && window.nkt[arrayName].indexOf(msgObj.uid) === -1)
            || !msgObj.uid
        ) {
            if (!msgObj.uid) {
                logIfVerbose(arrayName + ' NO UID IN');
                logIfVerbose(msgObj);
                return Promise.reject();
            }
            addToMessageArray(msgObj.uid, arrayName);
            return Promise.resolve();
        }
        return Promise.reject();
        /*
        return hashMessageObject(msgObj).then( (hashBuffer) => {
            let const = toHexString(new Uint8Array(hashBuffer));
            //logIfVerbose('checking not already in')
            //logIfVerbose(str);
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
        //logIfVerbose('GENERIC MESSAGE : ');
        //logIfVerbose(data);
        if (Object(data) === data) {
            if (data.msgFrom && window.nkt.userList[data.msgFrom]) window.nkt.userList[data.msgFrom].isUnreachable = false; //heard from
            //if (!data.ping && window.nkt.singleSwarmID && (data.msgType === 'encrypted' || data.msgType === 'bugoutEncrypted')) {
            //if (!data.ping && window.nkt.singleSwarmID && (data.msgType === 'encrypted' || data.msgType === 'bugoutEncrypted')) {
            if (!data.ping) {// BRIDGING PEERS
                if (data.fromChannel === 'webrtc') {
                    //delete data.fromChannel;
                    checkNotAlreadyIn(data, 'resentMessages').then(()=>{
                        window.nkt.websocket.emit(window.nkt.websocketEventName, data);
                    }).catch(()=>{});
                } else if (data.fromChannel === 'websocket') {
                    //delete data.fromChannel;
                    checkNotAlreadyIn(data, 'resentMessages').then(()=>{
                        window.nkt.mySwarm.send(data);
                    }).catch(()=>{});
                }
                //resilientSend(message); // resend if not a ping
            }
        }
        window.dispatchEvent(new CustomEvent('nktincomingdata', {
            detail: { data }
        }));
    }

    const startAskingForPreKey = (forAddr) => {
        if (
            !window.nkt.userList[forAddr]
            || window.nkt.userList[forAddr].preKey
            //|| window.nkt.userList[forAddr].isUnreachable
        ) return;
        //logIfVerbose('asking for ' + forAddr + '  prekey ...');
        window.nkt.userList[forAddr].preKeyRequestCount = window.nkt.userList[forAddr].preKeyRequestCount || 0;
        window.nkt.userList[forAddr].preKeyRequestCount++;
        resilientSend({
            msgType: 'preKeyRequest',
            msgFrom: window.nkt.mySwarm.address(),
            msgBugoutPk: window.nkt.mySwarm.pk,
            msgBugoutEk: window.nkt.mySwarm.ek,
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
            identityKey: signalUtil.toString(bundle.identityKey),
            registrationId: bundle.registrationId,
            preKey: {
                keyId: bundle.preKey.keyId,
                publicKey: signalUtil.toString(bundle.preKey.publicKey)
            },
            signedPreKey: {
                keyId: bundle.signedPreKey.keyId,
                publicKey: signalUtil.toString(bundle.signedPreKey.publicKey),
                signature: signalUtil.toString(bundle.signedPreKey.signature)
            }
        });
    }

    const stringToPreKeyBundle = (string) => {
        const bundle = JSON.parse(string);
        return {
            identityKey: signalUtil.toArrayBuffer(bundle.identityKey),
            registrationId: bundle.registrationId,
            preKey: {
                keyId: bundle.preKey.keyId,
                publicKey: signalUtil.toArrayBuffer(bundle.preKey.publicKey)
            },
            signedPreKey: {
                keyId: bundle.signedPreKey.keyId,
                publicKey: signalUtil.toArrayBuffer(bundle.signedPreKey.publicKey),
                signature: signalUtil.toArrayBuffer(bundle.signedPreKey.signature)
            }
        };
    }

    const answerPreKeyRequest = (fromAddr, forAddr) => {
        logIfVerbose('ANSWERING PREKEY REQUEST')
        if (forAddr === window.nkt.mySwarm.address()) {//anwser for me
            resilientSend({
                msgType: 'preKey',
                msgData: preKeyBundleToString(window.nkt.userList[fromAddr].myNewPreKeyBundle || window.nkt.preKeyBundle),
                msgDate: (new Date()).getTime().toString(),
                msgFrom: window.nkt.mySwarm.address(),
                msgBugoutPk: window.nkt.mySwarm.pk,
                msgBugoutEk: window.nkt.mySwarm.ek,
                msgTo: fromAddr
            });
        } else if(
            Object(window.nkt.userList[forAddr]) === window.nkt.userList[forAddr]
            && window.nkt.userList[forAddr].preKey
            && false // too much spam for now TODO : send only active peers' keys + not necessarily using same prekey
        ) {//answer for others if i know ?
            resilientSend({
                msgType: 'preKey',
                msgData: preKeyBundleToString(window.nkt.userList[forAddr].preKey),
                msgDate: (new Date()).getTime().toString(),
                msgFrom: forAddr,
                msgBugoutPk: window.nkt.mySwarm.pk,
                msgBugoutEk: window.nkt.mySwarm.ek,
                msgTo: fromAddr
            });
        }
    }

    const savePreKeyAnswer = (e, force) => {
        const preKey = stringToPreKeyBundle(e.detail.data.msgData);
        const addr = e.detail.data.msgFrom;
        //logIfVerbose('RECEIVED PREKEY');
        //logIfVerbose(preKey);
        //logIfVerbose(window.nkt.userList[addr]);
        //clearTimeout(window.nkt.userList[addr].askingForPreKeyTimeout);
        if (
            Object(window.nkt.userList[addr]) === window.nkt.userList[addr]
            && (!window.nkt.userList[addr].preKey || force)
        ) {
            if (window.nkt.userList[addr].waitForPeerToDestroySession) return;
            //window.nkt.userList[addr].receivedPreKey = true;
            window.nkt.userList[addr].preKey = preKey;
            //if (addr < window.nkt.mySwarm.address()) { // ONLY ONE OF THE TWO PEERS STARTS SESSION
            if (!force && addr < window.nkt.mySwarm.address()) {
                askPeerToReEstablishSession(addr);
            }
                //startSignalSessionWith(addr);
            //}
        }
    }

    const sendEncryptedMessage = (str, msgTo) => { // msgTo optional, private message
        const cont = window.dispatchEvent(new CustomEvent('nktsendingmessage', { detail: str }));
        if (!cont) return;
        resilientSend({
            msgType: 'humanMessage',
            msgData: str,
            msgDate: (new Date()).getTime().toString(),
            msgFrom: window.nkt.mySwarm.address(),
            msgBugoutEk: window.nkt.mySwarm.ek,
            msgBugoutPk: window.nkt.mySwarm.pk
        }, true, msgTo);
    }

    const sendClearMessage = (str) => {
        if (
            Object(str) === str
            && str.pubKeySrc
        ) {
            clearInterval(window.nkt.preload);
        }
        resilientSend({
            msgType: 'humanMessage',
            msgData: str,
            msgDate: (new Date()).getTime().toString(),
            msgBugoutPk: window.nkt.mySwarm.pk,
            msgBugoutEk: window.nkt.mySwarm.ek,
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
                    logIfVerbose('sending ' + event.detail)
                }
            }
        });
    }

    const askPeerToReEstablishSession = (addr) => {
        if (window.nkt.userList[addr].receivedOrderToEstablish) return;
        resilientSend({
            msgType: 'sessionEstablishmentOrder',
            msgData:  preKeyBundleToString(window.nkt.userList[addr].myNewPreKeyBundle || window.nkt.preKeyBundle),
            msgDate: (new Date()).getTime().toString(),
            msgFrom: window.nkt.mySwarm.address(),
            msgBugoutPk: window.nkt.mySwarm.pk,
            msgBugoutEk: window.nkt.mySwarm.ek,
            msgTo: addr
        }, false);
    }

    const askPeerToDestroySession = (addr) => {
        resilientSend({
            msgType: 'sessionDestroyOrder',
            msgDate: (new Date()).getTime().toString(),
            msgFrom: window.nkt.mySwarm.address(),
            msgBugoutPk: window.nkt.mySwarm.pk,
            msgBugoutEk: window.nkt.mySwarm.ek,
            msgTo: addr
        }, false);
    }

    const askPeerToUseSignalForMe = (addr) => {
        resilientSend({
            msgType: 'signalEnableOrder',
            msgDate: (new Date()).getTime().toString(),
            msgFrom: window.nkt.mySwarm.address(),
            msgBugoutPk: window.nkt.mySwarm.pk,
            msgBugoutEk: window.nkt.mySwarm.ek,
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
            decryptMessageFrom(e.detail.data.msgData, e.detail.data.msgFrom, e.detail.data.msgCipherType).then((plaintext) => {
                try {
                    const msg = JSON.parse(plaintext);
                    if (msg.msgType !== 'humanMessage') return;
                    window.dispatchEvent(new CustomEvent('nktencryptedmessagereceived', { detail: msg.msgData }));
                } catch (e) { logIfVerbose(e); }
            }).catch(err => logIfVerbose(err))
        });

        window.addEventListener('nktincomingdata', (e) => {
            if (
                !e.detail.data.msgData
                || !e.detail.data.msgType
                || !e.detail.data.msgTo
                || !e.detail.data.msgFrom
            ) return;
            if (
                e.detail.data.msgType !== 'bugoutEncrypted'
                || e.detail.data.msgTo !== window.nkt.mySwarm.address()
                || e.detail.data.msgTo === e.detail.data.msgFrom
            ) return;
            window.dispatchEvent(new CustomEvent('nktencryptedmessagereceived', { detail: e.detail.data.msgData }));
        });

        // Signal
        window.addEventListener('nktnewpeer', (e) => {
            startAskingForPreKey(e.detail.data.addr);
        });
        window.addEventListener('nktincomingdata', (e) => {
            if (e.detail.data.msgType === 'preKeyRequest') {
                //if (window.nkt.userList[e.detail.data.msgFrom].gotOk) return;
                if (!e.detail.data.msgFrom) return;
                answerPreKeyRequest(e.detail.data.msgFrom, e.detail.data.msgForAddr);
            }
        });
        window.addEventListener('nktincomingdata', (e) => {
            if (e.detail.data.msgType === 'preKey') {
                /*
                if (
                    window.nkt.userList[e.detail.data.msgFrom]
                    && window.nkt.userList[e.detail.data.msgFrom].gotOk
                ) return;
                */
                savePreKeyAnswer(e);
            }
        });
        window.addEventListener('nktincomingdata', (e) => {
            if (e.detail.data.msgType === 'sessionEstablishment') {
                if (e.detail.data.msgTo !== window.nkt.mySwarm.address()) return;
                //window.nkt.userList[e.detail.data.msgFrom].receivedSessionEstablishment = true;
                
                //if (!window.nkt.userList[e.detail.data.msgFrom].sessionCipher) return;
                //if (window.nkt.userList[e.detail.data.msgFrom].gotOk) return;
                //if (window.nkt.userList[e.detail.data.msgFrom].pauseSessionEstablishmentParsing) return;
                
                //window.nkt.userList[e.detail.data.msgFrom].pauseSessionEstablishmentParsing = true;
               //if (window.nkt.userList[e.detail.data.msgFrom].useSignal) return;
                if (window.nkt.userList[e.detail.data.msgFrom].receivedOrderToEstablish) return;
                logIfVerbose('PARSING SESSION ESTABLISHMENT FROM ' + e.detail.data.msgFrom);
                logIfVerbose(e.detail);
                //const detail = JSON.parse(JSON.stringify(e.detail));
                const detail = e.detail;
                (detail => {
                    decryptMessageFrom(detail.data.msgData, detail.data.msgFrom, detail.data.msgCipherType).then((plaintext) => {
                    logIfVerbose('decrypted session establishment :');
                    logIfVerbose(plaintext);
                    if (plaintext === window.nkt.mySwarm.address()) {
                        window.nkt.userList[detail.data.msgFrom].sessionEstablished = true;
                        askPeerToUseSignalForMe(detail.data.msgFrom);
                        logIfVerbose('ENABLING SIGNAL FOR ' + detail.data.msgFrom);
                        window.nkt.userList[detail.data.msgFrom].useSignal = true;
                        /*
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
                        */
                    } else {
                        logIfVerbose('BAD SESSION ESTABLISHMENT');
                        logIfVerbose(detail);

                        
                        window.nkt.userList[detail.data.msgFrom].receivedOrderToEstablish = false;
                        //window.nkt.userList[detail.data.msgFrom].waitForPeerToDestroySession = true;// ROLLBACK
                        //window.nkt.userList[detail.data.msgFrom].useSignal = false;
                        generateNewPreKeyBundle(window.nkt.signalStore, 1, 1).then((preKeyBundle) => {
                            window.nkt.userList[detail.data.msgFrom].preKey = null;
                            window.nkt.userList[detail.data.msgFrom].myNewPreKeyBundle = preKeyBundle;
                            startAskingForPreKey(detail.data.msgFrom);
                            //askPeerToDestroySession(detail.data.msgFrom);// ROLLBACK
                        });
                        //logIfVerbose('try the other way');

                        //window.location.reload();


                        /*
                        window.nkt.userList[detail.data.msgFrom].waitForPeerToEstablishSession = false;
                        window.nkt.userList[detail.data.msgFrom].receivedOrderToEstablish = true;
                        window.nkt.signalStore.removeSession(detail.data.msgFrom + '.1');
                        askPeerToDestroySession(detail.data.msgFrom);
                        */


                        //window.nkt.userList[detail.data.msgFrom].pauseSessionEstablishmentParsing = false;
                        /*
                        window.nkt.signalStore.removeSession(detail.data.msgFrom + '.1');
                        if (window.nkt.userList[detail.data.msgFrom].waitingForPeerToEstablish) {
                            //my turn
                            setTimeout(()=>{
                                if (!window.nkt.userList[detail.data.msgFrom].sessionEstablished) {
                                    window.nkt.userList[detail.data.msgFrom].waitingForPeerToEstablish = false;
                                        startSignalSessionWith(e.detail.data.msgFrom);
                                    }
                            }, 100);
                        } else if (!window.nkt.userList[detail.data.msgFrom].sessionEstablished) {
                            //delete window.nkt.userList[e.detail.data.msgFrom];
                            //startSignalSessionWith(e.detail.data.msgFrom);
                            window.nkt.userList[detail.data.msgFrom].waitingForPeerToEstablish = true;
                            setTimeout(()=>{
                                if (!window.nkt.userList[detail.data.msgFrom].sessionEstablished) {
                                        logIfVerbose('asking '+ detail.data.msgFrom +' to reestablish session')
                                        askPeerToReEstablishSession(detail.data.msgFrom);
                                    }
                            }, 100);
                            //logIfVerbose('prekey known for peer is');
                            //logIfVerbose(window.nkt.userList[e.detail.data.msgFrom].preKey);
                            //logIfVerbose('my prekey is');
                            //logIfVerbose(window.nkt.preKeyBundle);
                            //clearInterval(window.nkt.userList[e.detail.data.msgFrom].keepSendingSessionEstablishment);
                            //startSignalSessionWith(e.detail.data.msgFrom);
                            
                            
                        }
                        */
                    }
                }).catch((err) => {
                    logIfVerbose('CANNOT DECRYPT SESSION ESTABLISHMENT');
                    logIfVerbose(err);
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
            if (e.detail.data.msgType === 'sessionEstablishmentOrder') {// && false) { // nope (MAC ERROR)
                if (e.detail.data.msgTo !== window.nkt.mySwarm.address()) return;
                //if (window.nkt.userList[e.detail.data.msgFrom].gotOk) return;
                logIfVerbose('RECEIVED ORDER TO REESTABLISH');
                window.nkt.userList[e.detail.data.msgFrom].receivedOrderToEstablish = true;
                //clearInterval(window.nkt.userList[e.detail.data.msgFrom].keepSendingSessionEstablishment);
                savePreKeyAnswer(e, true);
                startSignalSessionWith(e.detail.data.msgFrom);
            }
        });

        window.addEventListener('nktincomingdata', (e) => {
            if (e.detail.data.msgType === 'signalEnableOrder') {
                if (e.detail.data.msgTo !== window.nkt.mySwarm.address()) return;
                logIfVerbose('ENABLING SIGNAL FOR' + e.detail.data.msgFrom);
                window.nkt.userList[e.detail.data.msgFrom].useSignal = true;
            }
        });

        const destroySession = (addr) => {
            setTimeout(()=>{
                if (window.nkt.userList[addr].useSignal) return;
                //generateNewPreKeyBundle(window.nkt.signalStore, 1, 1).then((preKeyBundle) => {
                    //logIfVerbose(window.nkt.signalStore);
                    //window.nkt.userList[addr].myNewPreKeyBundle = preKeyBundle;

                    /* ROLLBACK
                    window.nkt.signalStore.removeSession(addr + '.1');
                    window.nkt.userList[addr].receivedOrderToEstablish = false;
                    window.nkt.userList[addr].preKey = null;
                    window.nkt.userList[addr].sessionCipher = null;
                    */
                    resilientSend({
                        msgType: 'sessionDestroyed',
                        msgDate: (new Date()).getTime().toString(),
                        msgFrom: window.nkt.mySwarm.address(),
                        msgBugoutPk: window.nkt.mySwarm.pk,
                        msgBugoutEk: window.nkt.mySwarm.ek,
                        msgTo: addr
                    }, false);
                    startAskingForPreKey(addr);
                //});
            }, 10000);
        }

        
        window.addEventListener('nktincomingdata', (e) => {
            if (e.detail.data.msgType === 'sessionDestroyOrder') {
                if (e.detail.data.msgTo !== window.nkt.mySwarm.address()) return;
                destroySession(e.detail.data.msgFrom);
            }
        });


        window.addEventListener('nktincomingdata', (e) => {
            if (e.detail.data.msgType === 'sessionDestroyed') {
                if (e.detail.data.msgTo !== window.nkt.mySwarm.address()) return;
                //window.nkt.signalStore.remove('identityKey' + e.detail.data.msgFrom);
                /* ROLLBACK
                window.nkt.signalStore.removeSession(e.detail.data.msgFrom + '.1');
                window.nkt.userList[e.detail.data.msgFrom].receivedOrderToEstablish = false;
                window.nkt.userList[e.detail.data.msgFrom].preKey = null;
                window.nkt.userList[e.detail.data.msgFrom].sessionCipher = null;
                window.nkt.userList[e.detail.data.msgFrom].waitForPeerToDestroySession = false;
                startAskingForPreKey(e.detail.data.msgFrom);
                */
               
            }
        });

        /*
        
        window.addEventListener('nktincomingdata', (e) => {
            if (e.detail.data.msgType === 'sessionEstablishmentOk') {
                if (e.detail.data.msgTo !== window.nkt.mySwarm.address()) return;
                if (window.nkt.userList[e.detail.data.msgFrom].gotOk) return;
                logIfVerbose('GOT OK FROM ' + e.detail.data.msgFrom);
                window.nkt.userList[e.detail.data.msgFrom].pauseSessionEstablishmentParsing = true;
                //clearInterval(window.nkt.userList[e.detail.data.msgFrom].keepSendingSessionEstablishment);
                window.nkt.userList[e.detail.data.msgFrom].gotOk = true;
            }
        });
        */
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

    const logIfVerbose = (msg) => {
        if (window.nktVerbose) {
            console.log(msg);
        }
    }

    ; ( () => {
        window.nkt = {};
        window.nkt.singleSwarmID = "nktRYLi0Sn7BEQSPfo3KOiewur1gec";
        window.nkt.trackers = [
            "wss://hub.bugout.link",
            "wss://tracker.openwebtorrent.com",
            "wss://tracker.btorrent.xyz",
        ];
        window.nkt.iceServers = [
            {
                urls: [
                    'stun:stun.l.google.com:19302',
                    'stun:global.stun.twilio.com:3478',
                    'stun:stun.avigora.fr:3478',
                    'stun:stun.1und1.de:3478'
                ]
            }
        ];
        window.nkt.userList = {};
        window.nkt.sentMessages = [];
        window.nkt.resentMessages = [];
        window.nkt.receivedMessages = [];
        if (window.location.href.indexOf('localhost') > -1) {
            window.nkt.trackers.push("ws://localhost:8000");
            window.nkt.websocket = io('http://localhost:3000');
            window.nkt.websocketEventName = 'nkt';
            window.nktVerbose = true;
        } else {
            window.nkt.websocket = io("wss://" + window.location.hostname);
            window.nkt.websocketEventName = 'corev2';
        }
        window.nkt.mySwarm = startWebRTCServer();
        signalInit().then((arr) => {
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

        //window.nkt.preload = setInterval(()=>sendClearMessage({ping: Math.random.toString()}), 500);
        sendClearMessage({ping: Math.random.toString()});

    })();
})();