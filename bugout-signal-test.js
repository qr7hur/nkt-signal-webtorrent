/**
 * Dependencies : libsignal-protocol, bugout, bencode, nacl, bs58
 */
; ( () => {

    /**
     * Generates pseudorandom string
     * Used to generate message uid
     */
    const genRandomStr = () => {
        return toHexString(
            window.crypto.getRandomValues(new Uint32Array(10))
        );
    }

    /**
     * Kind of an ascii-armoring functon (maps utf-8 to smaller character space)
     * Used before encryption
     * @param {string} str unsafe string
     */
    const utf8_to_b64 = (str) => {
        return window.btoa(unescape(encodeURIComponent(str)));
    }

    /**
     * Reverses utf8_to_b64()
     * @param {string} str safe string
     */
    const b64_to_utf8 = (str) => {
        return decodeURIComponent(escape(window.atob(str)));
    }

    /**
     * Converts byte array to hexadecimal string
     * Used in genRandomStr()
     * @param {Uint32Array} byteArray byte array
     */
    const toHexString = (byteArray) => {
        return Array.prototype.map.call(byteArray, (byte) => {
            return ('0' + (byte & 0xFF).toString(16)).slice(-2);
        }).join('');
    }

    /**
     * Generates signal identity key and registration ID (called once, upon initialization)
     * @param {Object} store libSignal SignalProtocolStore (in-memory)
     */
    const generateIdentity = (store) => {
        return Promise.all([
            libsignal.KeyHelper.generateIdentityKeyPair(),
            libsignal.KeyHelper.generateRegistrationId(),
        ]).then( (result) => {
            store.put('identityKey', result[0]);
            store.put('registrationId', result[1]);
        });
    }

    /**
     * Generates one initial preKey and the signed preKey
     * @param {Object} store libSignal SignalProtocolStore (in-memory)
     * @param {number} preKeyId First preKey, so most likely 1 (warning : 0 unsupported)
     * @param {number} signedPreKeyId First and only signed preKey, so most likely 1 (warning : 0 unsupported)
     */
    const generatePreKeyBundle = (store, preKeyId, signedPreKeyId) => {
        return Promise.all([
            store.getIdentityKeyPair(),
            store.getLocalRegistrationId()
        ]).then( (result) => {
            const identity = result[0];
            const registrationId = result[1];
            return Promise.all([
                libsignal.KeyHelper.generatePreKey(preKeyId),
                libsignal.KeyHelper.generateSignedPreKey(identity, signedPreKeyId),
            ]).then( (keys) => {
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

    /**
     * Generates one more preKey and loads the signed preKey
     * @param {Object} store libSignal SignalProtocolStore (in-memory)
     * @param {number} preKeyId
     *  Additional preKey, 
     *  but also most likely 1 because called when no preKey remaining
     *  (warning : 0 unsupported)
     * @param {number} signedPreKeyId First and only signed preKey, so most likely 1 (warning : 0 unsupported)
     */
    const generateNewPreKeyBundle = (store, preKeyId, signedPreKeyId) => {
        return Promise.all([
            store.getIdentityKeyPair(),
            store.getLocalRegistrationId()
        ]).then( (result) => {
            const identity = result[0];
            const registrationId = result[1];
            return Promise.all([
                libsignal.KeyHelper.generatePreKey(preKeyId),
                store.loadSignedPreKey(signedPreKeyId)
            ]).then( (keys) => {
                const preKey = keys[0]
                const signedPreKey = keys[1];
                store.storePreKey(preKeyId, preKey.keyPair);
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

    /**
     * Instantiates libSignal SignalProtocolStore (in-memory)
     * Uses it to store identity and initial preKey bundle
     */
    const signalInit = () => {
        const bobStore = new libsignal.SignalProtocolStore();
        const bobPreKeyId = 1;
        const bobSignedKeyId = 1;
        if (!window.nkt.signalStore) {
            return generateIdentity(bobStore).then( () => {
                return Promise.all([
                    generatePreKeyBundle(bobStore, bobPreKeyId, bobSignedKeyId),
                    Promise.resolve(bobStore)
                ]);
            });
        }
    }

    /**
     * Sends an initial encrypted message which should contain a preKey bundle
     * Used to test peer capacity to use existing preKey or force generation of a new one
     * @param {string} addr address of a known peer 
     */
    const sendSessionEstablishment = (addr) => {
        const bobStore = window.nkt.signalStore;
        const originalMessage = utf8_to_b64(addr); // for double check on arrival
        const ALICE_DEVICE_ID = 1;
        const ALICE_ADDRESS = new libsignal.SignalProtocolAddress(addr, ALICE_DEVICE_ID);
        window.nkt.userList[addr].sessionCipher = new libsignal.SessionCipher(bobStore, ALICE_ADDRESS);
        window.nkt.userList[addr].sessionCipher.encrypt(
            originalMessage
        ).then( (ciphertext) => {
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
        }).catch( (err) => {
            logIfVerbose('encrypt err');
            logIfVerbose(err);
        });
    }

    /**
     * Builds a signal session with a known peer (consumes a preKey)
     * There should be one unique session for each peer
     * @param {string} addr address of a known peer 
     */
    const startSignalSessionWith = (addr) => {
        if (!window.nkt.userList[addr].receivedOrderToEstablish) {
            return;
        }
        const ALICE_DEVICE_ID = 1;
        const ALICE_ADDRESS = new libsignal.SignalProtocolAddress(addr, ALICE_DEVICE_ID);
        const builder = new libsignal.SessionBuilder(window.nkt.signalStore, ALICE_ADDRESS);
        const preKeyBundle = window.nkt.userList[addr].preKey;
        logIfVerbose('starting signal session with ' + addr);
        if (!window.nkt.userList[addr]) {
            return;
        }
        return (
            builder.processPreKey(
                preKeyBundle
            ).then( () =>
                sendSessionEstablishment(addr)
            ).catch( (err) => {
                logIfVerbose('ERROR IN startsignalsession');
                logIfVerbose(err);
            })
        );
    }

    /**
     * Decrypts an encrypted preKey signal message from a given peer.
     * Instantiates and stores signal session with the peer.
     * The preKey message is the first message of the session,
     * has cipherType 3 and contains a preKey bundle of the peer
     * @param {Object} message data encrypted by libsignal
     * @param {string} from address of sender
     */
    const decryptPreKeyMessageFrom = (message, from) => {
        logIfVerbose('DECRYPTING');
        const ALICE_DEVICE_ID = 1;
        const ALICE_ADDRESS = new libsignal.SignalProtocolAddress(from, ALICE_DEVICE_ID);
        const bobStore = window.nkt.signalStore; 
        const aliceSessionCipher = new libsignal.SessionCipher(bobStore, ALICE_ADDRESS);
        window.nkt.userList[from].sessionCipher = aliceSessionCipher;
        return (
            aliceSessionCipher.decryptPreKeyWhisperMessage(
                message, 'binary'
            ).then( (plaintext) => 
                Promise.resolve(b64_to_utf8(signalUtil.toString(plaintext)))
            ).catch( (err) => {
                logIfVerbose('decryptPreKeyWhisperMessage error');
                logIfVerbose(err);
            })
        );
    }

    /**
     * Decrypts a signal-encrypted message from a given peer
     * Resorts to decryptPreKeyMessageFrom() on cipherType === 3
     * @param {Object} message data encrypted by libsignal
     * @param {string} from address of sender
     * @param {number} cipherType 3 or else ... (3 if initial message)
     */
    const decryptMessageFrom = (message, from, cipherType) => {
        if (cipherType === 3) {
            return decryptPreKeyMessageFrom(message, from);
        }
        if (window.nkt.userList[from].sessionCipher) {
            return (
                window.nkt.userList[from].sessionCipher.decryptWhisperMessage(
                    message, 'binary'
                ).then( (plaintext) =>
                    Promise.resolve(b64_to_utf8(signalUtil.toString(plaintext)))
                ).catch( (err) => {
                    logIfVerbose('decryptWhisperMessage error');
                    logIfVerbose(err);
                })
            );
        } else {
            logIfVerbose('received non prekey message but got no session yet');
            return Promise.reject();
        }
    }

    /**
     * Uses an established signal session to encrypt a message for a given peer
     * @param {string} message string or stringified object to encrypt
     * @param {string} to address of recipient peer
     */
    const encryptMessageTo = (message, to) => {
        const bobSessionCipher = window.nkt.userList[to].sessionCipher;
        if (!bobSessionCipher) {
            return Promise.reject('no session yet');
        }
        return bobSessionCipher.encrypt(utf8_to_b64(message));
    }

    /**
     * Uses Bugout to participate in a globally unique web torrent through webrtc
     * Generates address of self (and bugout keys).
     * Fires the 'nktwebrtcseen' and 'nktwebrtcleft' events.
     * @fires nktwebrtcseen { e.detail.addr }
     * @fires nktwebrtcleft { e.detail.addr } (less reliable)
     */
    const startWebRTCServer = () => {
        const b = new Bugout(window.nkt.singleSwarmID, {
            "announce": window.nkt.trackers,
            "iceServers": window.nkt.iceServers
        });
        //b.heartbeat(2000);
        b.on('message', (address, message) => {
            handleMessageFromSwarm(address, message);
        });
        b.on('seen', (addr) => {
            logIfVerbose('RTC SEEN');
            logIfVerbose(addr);
            window.dispatchEvent(
                new CustomEvent('nktwebrtcseen', { detail: addr })
            );
        });
        b.on('left', (addr) => {
            logIfVerbose('RTC LEFT');
            logIfVerbose(addr);
            window.dispatchEvent(
                new CustomEvent('nktwebrtcleft', { detail: addr })
            );
        });
        return b;
    }

    /**
     * Entry point for incoming websocket messages
     * Dispatches to peer identification functions then message reception handler
     * @param {Object} message { msgFrom, msgType, msgTo, msgData, msgBugoutPk, msgBugoutEk }
     */
    const handlePingFromWebSocket = (message) => {
        if (Object(message) === message) {
            const addr = message.msgFrom;
            const bugoutPk = message.msgBugoutPk;
            const bugoutEk = message.msgBugoutEk;
            switch (message.msgType) {
                case 'newSwarmAddress':
                    if (!window.nkt.userList[addr]) {
                        handleUnknownSwarmAddress(addr, bugoutPk, bugoutEk);
                    }
                    break;
                default:
                    if (!window.nkt.userList[addr]) {
                        handleUnknownSwarmAddress(addr, bugoutPk, bugoutEk);
                    }
                    checkNotAlreadyIn(
                        message, 'receivedMessages'
                    ).then( () => {
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
                    }).catch( () => {
                        //logIfVerbose('already received');
                        //do nothing
                    })
                    break;
            }
        }
    }

    /**
     * Handles new peer recognition on incoming messages from websocket
     * Fires the 'nktnewpeer' event
     * @param {string} addr peer address to be tested
     * @param {string} bugoutPk bugout public key used for signature
     * @param {string} bugoutEk bugout public key used for encryption
     * @fires nktnewpeer { e.detail.data.addr }
     */
    const handleUnknownSwarmAddress = (addr, bugoutPk, bugoutEk) => {
        if (addr === window.nkt.mySwarm.address()) {
            return;
        }
        window.nkt.userList[addr] = {};
        if (!window.nkt.mySwarm.peers[addr]) {
            window.nkt.mySwarm.peers[addr] = {
                pk: bugoutPk,
                ek: bugoutEk,
                last: 0
            };
        }
        window.dispatchEvent(new CustomEvent('nktnewpeer', {
            detail: { data: { addr } }
        }));
    }

    /**
     * Handles new peer recognition on incoming messages from webrtc
     * Fires the 'nktnewpeer' event.
     * @param {string} addr address through which the message has been received (peer or bridge/relay peer)
     * @param {string} userId address of the peer
     * @param {string} bugoutPk bugout public key used for signature
     * @param {string} bugoutEk bugout public key used for encryption
     * @fires nktnewpeer { e.detail.data.addr }
     */
    const setClientAddressForSwarmPeer = (addr, userId, bugoutPk, bugoutEk) => {
        if (userId === window.nkt.mySwarm.address()) {
            return;
        }
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

    /**
     * An attempt to prevent memory leak on unreachable peers...
     */
    const removeUnreachableWires = () => {
        let toSplice = [];
        if (Object(window.nkt.mySwarm.torrent) === window.nkt.mySwarm.torrent) {
            if (Array.isArray(window.nkt.mySwarm.torrent.wires)) {
                for (let i = 0; i < window.nkt.mySwarm.torrent.wires.length; i++) {
                    let wire = window.nkt.mySwarm.torrent.wires[i];
                    if (Object(wire) === wire && Object(wire._readableState) === wire._readableState) {
                        if (Object(wire._readableState.buffer) === wire._readableState.buffer) {
                            if (wire._readableState.buffer.length && wire._readableState.buffer.length > 1024) {
                                toSplice.push(i);
                            }
                        }
                    }
                }
            }
        }
        for (let index of toSplice) {
            window.nkt.mySwarm.torrent.wires.splice(index, 1);
        }
    }

    /**
     * Starts a timer to repeatedly send self address to all peers
     */
    const beginSwarmAddrBroadcast = () => {
        resilientSend({
            msgType: 'newSwarmAddress',
            msgFrom: window.nkt.mySwarm.address(),
            msgBugoutPk: window.nkt.mySwarm.pk,
            msgBugoutEk: window.nkt.mySwarm.ek,
            msgDate: (new Date()).getTime().toString()
        });
        removeUnreachableWires();
        setTimeout(beginSwarmAddrBroadcast, 5000);
    }

    /**
     * Entry point for incoming webrtc messages
     * @param {string} address address through which the message has been received (peer or bridge/relay peer)
     * @param {Object} message { msgFrom, msgType, msgTo, msgData, msgBugoutPk, msgBugoutEk }
     */
    const handleMessageFromSwarm = (address, message) => {
        if (Object(message) === message && message.msgFrom) {
            setClientAddressForSwarmPeer(
                address,
                message.msgFrom,
                message.msgBugoutPk,
                message.msgBugoutEk
            );
        }
        checkNotAlreadyIn(
            message, 'receivedMessages'
        ).then( () => {
            message.fromChannel = 'webrtc';
            handleNewMessageReceived(message);
        }).catch( () => {
            //logIfVerbose('already received');
            //do nothing
        });
    }

    /**
     * Copied from bugout lib
     * To be used at this layer before (or in case of failure of) Signal session establishment
     * Outputs bittorrent-formatted data
     * @param {Object} bugout Bugout instance (as returned by startWebRTCServer())
     * @param {Object} params The only message type used here is : {"y":"m","v": JSON.stringify(msg)}
     */
    function bugoutMakePacket(bugout, params) {
        var p = {
          "t": (new Date()).getTime(),
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

    /**
     * Copied from bugout lib
     * To be used at this layer before (or in case of failure of) Signal session establishment
     * Encrypts a message for a peer for whom we don't have a Signal session (yet)
     * @param {Object} bugout Bugout instance (as returned by startWebRTCServer())
     * @param {string} pk public key of recipient peer
     * @param {string} packet bittorrent message as formatted by bugoutMakePacket()
     */
    const bugoutEncrypt = (bugout, pk, packet) => {
        if (bugout.peers[bugout.address(pk)]) {
            var nonce = nacl.randomBytes(nacl.box.nonceLength);
            packet = bencode.encode({
                "n": nonce,
                "ek": bs58.encode(Buffer.from(bugout.keyPairEncrypt.publicKey)),
                "e": nacl.box(
                    packet,
                    nonce,
                    bs58.decode(bugout.peers[bugout.address(pk)].ek),
                    bugout.keyPairEncrypt.secretKey
                ),
            });
        } else {
            throw bugout.address(pk) + " not seen - no encryption key.";
        }
        return packet;
    }

    /**
     * Copied from bugout lib
     * To be used at this layer before (or in case of failure of) Signal session establishment
     * Decrypts a message from a peer for whom we don't have a Signal session (yet)
     * @param {Object} bugout Bugout instance (as returned by startWebRTCServer())
     * @param {string} message incoming bittorrent message
     */
    const bugoutDecrypt = (bugout, message) => {
        var unpacked = bencode.decode(message);
        // if this is an encrypted packet first try to decrypt it
        if (unpacked.e && unpacked.n && unpacked.ek) {
            var ek = unpacked.ek.toString();
            var decrypted = nacl.box.open(
                unpacked.e,
                unpacked.n,
                bs58.decode(ek),
                bugout.keyPairEncrypt.secretKey
            );
            if (decrypted) {
                unpacked = bencode.decode(decrypted);
            } else {
                unpacked = null;
            }
        }
        // if there's no data decryption failed
        if (unpacked && unpacked.p) {
            var packet = bencode.decode(unpacked.p);
            var pk = packet.pk.toString();
            var id = packet.i.toString();
            var checksig = nacl.sign.detached.verify(unpacked.p, unpacked.s, bs58.decode(pk));
            var checkid = id == bugout.identifier;
            var checktime = true;
            if (checksig && checkid && checktime) {
                // message is authenticated
                var ek = packet.ek.toString();
                // check packet types
                var messagestring = packet.v.toString();
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

    /**
     * Encrypts a message with bugout keys for a given peer
     * Sends it to all known peers both through websocket and webrtc (webtorrent)
     * Used only when no signal session can be found for this peer (hopefully only early messages)
     * @param {Object} msgObj { msgType, msgData, msgDate, msgFrom, msgBugoutEk, msgBugoutPk ... }
     * @param {string} msgTo address of recipient peer
     */
    const resilientBugoutEncryptedSend = (msgObj, msgTo) => {
        const msg = {
            msgDate: msgObj.msgDate,
            msgType: 'bugoutEncrypted',
            msgData: msgObj.msgData,
            msgTo,
            msgFrom: window.nkt.mySwarm.address(), 
            msgBugoutPk: window.nkt.mySwarm.pk,
            msgBugoutEk: window.nkt.mySwarm.ek,
            uid: genRandomStr()
        };
        window.nkt.mySwarm.send(msgTo, msg);
        window.nkt.websocket.emit(
            window.nkt.websocketEventName,
            {
                msgDate: msgObj.msgDate,
                msgType: 'bugoutEncrypted',
                msgData: bugoutEncrypt(
                    window.nkt.mySwarm,
                    window.nkt.mySwarm.peers[msgTo].pk,
                    bugoutMakePacket(
                        window.nkt.mySwarm,
                        {"y":"m","v": JSON.stringify(msg)}
                    )
                ),
                msgTo,
                msgFrom: window.nkt.mySwarm.address(), 
                msgBugoutPk: window.nkt.mySwarm.pk,
                msgBugoutEk: window.nkt.mySwarm.ek,
                uid: msg.uid
            }
        );
    }

    /**
     * Encrypts a message with a given signal session
     * Sends it to all known peers both through websocket and webrtc (webtorrent)
     * This is the preferred way to handle secure communication
     * @param {Object} msgObj { msgType, msgData, msgDate, msgFrom, msgBugoutEk, msgBugoutPk ... }
     * @param {string} msgTo address of recipient peer
     */
    const resilientSignalEncryptedSend = (msgObj, msgTo) => {
        encryptMessageTo(JSON.stringify(msgObj), msgTo).then( (ciphertext) => {
            const msg = {
                msgType: 'encrypted',
                msgData: ciphertext.body,
                msgTo,
                msgFrom: window.nkt.mySwarm.address(),
                msgCipherType: ciphertext.type,
                msgBugoutPk: window.nkt.mySwarm.pk,
                msgBugoutEk: window.nkt.mySwarm.ek,
                uid: genRandomStr()
            };
            window.nkt.websocket.emit(window.nkt.websocketEventName, msg);
            window.nkt.mySwarm.send(msg);
        }).catch((err) => {
            if (window.nkt.userList[msgTo].sessionCipher) {
                logIfVerbose('error sending encrypted msg');
                logIfVerbose(err);
            }
        });
    }

    /**
     * Sends a cleartext message to all known peers both through websocket and webrtc (webtorrent)
     * This is the preferred way to handle signalling
     * @param {Object} msgObj { msgType, msgData, msgDate, msgFrom, msgBugoutEk, msgBugoutPk ... }
     */
    const resilientClearSend = (msgObj) => {
        window.nkt.websocket.emit(window.nkt.websocketEventName, msgObj);
        window.nkt.mySwarm.send(msgObj);
    }

    /**
     * Chooses from the resilientBugoutEncryptedSend(), resilientSignalEncryptedSend() and resilientClearSend()
     * functions to send a message through all available channels.
     * Handles some level of deduplication to avoid flood
     * @param {Object} msgObj { msgType, msgData, msgDate, msgFrom, msgBugoutEk, msgBugoutPk ... }
     * @param {boolean} encryptedBool [optional] encryption flag
     * @param {string} msgTo [optional] address of recipient peer
     */
    const resilientSend = (msgObj, encryptedBool, msgTo) => {
        if (Object(msgObj) === msgObj) {
            msgObj.uid = msgObj.uid || genRandomStr();
        }
        return (
            checkNotAlreadyIn(
                msgObj, 'sentMessages'
            ).then( () => {
                const userList = window.nkt.userList;
                if (encryptedBool) {
                    for (let i in userList) {
                        if (userList[i].dontSendTo || userList[i].isUnreachable) {
                            continue; // TODO
                        }
                        if (msgTo && i !== msgTo) {
                            continue; // meh
                        }
                        if (!userList[i].useSignal) {
                            resilientBugoutEncryptedSend(msgObj, i);
                            continue;
                        }
                        resilientSignalEncryptedSend(msgObj, i);
                    }
                } else {
                    resilientClearSend(msgObj);
                }
            }).catch( (err) => {
                if (err) {
                    console.error(err);
                }
            })
        );
    }

    /**
     * Verifies the absence of a given message uid in a list of known uids
     * Prevents unnecessary flood
     * @param {Object} msgObj { uid, ...}
     * @param {string} arrayName name of a global uid stack window.nkt[arrayName]
     */
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
    }

    /**
     * Pushed uids to a global stack, not exceeding 1000 uids per stack
     * @param {string} uid could be a hash, but was changed to an uid for performance 
     * @param {string} arrayName name of a global uid stack window.nkt[arrayName]
     */
    const addToMessageArray = (uid, arrayName) => {
        if (window.nkt[arrayName].length > 1000) {
            window.nkt[arrayName].shift();
        }
        window.nkt[arrayName].push(uid);
    }

    /**
     * Handles a de-duplicated message coming from websocket, webrtc, or both
     * Allows peers to behave as brigdes between websocket and webrtc by re-sending all incoming messages
     * Fires the 'nktincomingdata' event
     * @param {Object} data received message object { msgType, msgData, msgDate, msgFrom, msgBugoutEk, msgBugoutPk ... }
     * @fires nktincomingdata { e.detail.data }
     */
    const handleNewMessageReceived = (data) => {
        if (Object(data) === data) {
            if (
                data.msgFrom
                && window.nkt.userList[data.msgFrom]
            ) {
                window.nkt.userList[data.msgFrom].isUnreachable = false; //heard from
            }
            if (!data.ping) {// BRIDGING PEERS
                if (data.fromChannel === 'webrtc') {
                    checkNotAlreadyIn(data, 'resentMessages').then(()=>{
                        window.nkt.websocket.emit(window.nkt.websocketEventName, data);
                    }).catch(()=>{});
                } else if (data.fromChannel === 'websocket') {
                    checkNotAlreadyIn(data, 'resentMessages').then(()=>{
                        window.nkt.mySwarm.send(data);
                    }).catch(()=>{});
                }
            }
        }
        window.dispatchEvent(
            new CustomEvent('nktincomingdata', {detail: { data }})
        );
    }

    /**
     * Starts sending preKey requests to a known peer.
     * To be started when we hear about a new peer and stopped when answered.
     * @param {string} forAddr address for whom we want to know an associated preKey
     */
    const startAskingForPreKey = (forAddr) => {
        if (
            !window.nkt.userList[forAddr]
            || window.nkt.userList[forAddr].preKey
            || window.nkt.userList[forAddr].useSignal
        ) {
            return;
        }
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
        if (window.nkt.userList[forAddr].preKeyRequestCount > 100) {
            delete window.nkt.userList[forAddr];
        } else {
            setTimeout(() => startAskingForPreKey(forAddr), 5000);
        }
    }

    /**
     * Converts a preKey bundle, containing array buffers, to stringified JSON
     * @param {Object} bundle preKey bundle
     *  { identityKey, registrationId, preKey: { keyId, publicKey }, signedPreKey: {keyId:, publicKey, signature } }
     */
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

    /**
     * Reverses preKeyBundleToString()
     * @param {string} string stringified JSON as returned by preKeyBundleToString()
     */
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

    /**
     * Answers a preKey request with our own preKey for sender peer
     * @param {string} fromAddr sender peer
     * @param {string} forAddr user address for whom the preKey request is targeted
     */
    const answerPreKeyRequest = (fromAddr, forAddr) => {
        if (forAddr === window.nkt.mySwarm.address()) {//anwser for me
            logIfVerbose('ANSWERING PREKEY REQUEST')
            resilientSend({
                msgType: 'preKey',
                msgData: preKeyBundleToString(
                    window.nkt.userList[fromAddr].myNewPreKeyBundle
                    || window.nkt.preKeyBundle
                ),
                msgDate: (new Date()).getTime().toString(),
                msgFrom: window.nkt.mySwarm.address(),
                msgBugoutPk: window.nkt.mySwarm.pk,
                msgBugoutEk: window.nkt.mySwarm.ek,
                msgTo: fromAddr
            });
        }
    }

    /**
     * Records preKey for a given peer if not already known or forced to refresh (in case of a session establishment order)
     * Avoids establishing a signal session with peers who are already establishing session with us.
     * @param {Object} e preKey message event { e.detail.data.msgType: 'preKey', e.detail.data.msgFrom, e.detail.data.msgData }
     * @param {boolean} force forces the recording of a new preKey for this peer
     */
    const savePreKeyAnswer = (e, force) => {
        const preKey = stringToPreKeyBundle(e.detail.data.msgData);
        const addr = e.detail.data.msgFrom;
        if (
            Object(window.nkt.userList[addr]) === window.nkt.userList[addr]
            && (!window.nkt.userList[addr].preKey || force)
        ) {
            if (window.nkt.userList[addr].waitForPeerToDestroySession) {
                return;
            }
            window.nkt.userList[addr].preKey = preKey;
            // ONLY ONE OF THE TWO PEERS STARTS SESSION
            if (!force && addr < window.nkt.mySwarm.address()) {
                askPeerToReEstablishSession(addr);
            }
        }
    }

    /**
     * High level API for sending encrypted messages.
     * This is the preferred way to handle secure communication.
     * Fires the 'nktsendingmessage' event
     * @param {Object} jsObj stringifiable javascript object
     * @param {string} msgTo [optional] address of recipient peer, if undefined, encrypts for each peer
     * @fires nktsendingmessage { e.detail }
     */
    const sendEncryptedMessage = (jsObj, msgTo) => {
        const cont = window.dispatchEvent(
            new CustomEvent('nktsendingmessage', { detail: jsObj })
        );
        if (!cont) {
            return;
        }
        resilientSend({
            msgType: 'forUpperLayer',
            msgData: jsObj,
            msgDate: (new Date()).getTime().toString(),
            msgFrom: window.nkt.mySwarm.address(),
            msgBugoutEk: window.nkt.mySwarm.ek,
            msgBugoutPk: window.nkt.mySwarm.pk
        }, true, msgTo);
    }

    /**
     * High level API for sending cleartext messages.
     * This is the preferred way to handle signalling.
     * @param {Object} jsObj stringifiable javascript object
     */
    const sendClearMessage = (jsObj) => {
        resilientSend({
            msgType: 'forUpperLayer',
            msgData: jsObj,
            msgDate: (new Date()).getTime().toString(),
            msgBugoutPk: window.nkt.mySwarm.pk,
            msgBugoutEk: window.nkt.mySwarm.ek,
            msgFrom: window.nkt.mySwarm.address()
        }, false);
    }

    /**
     * Sends an order to a peer for it to establish a signal session with us.
     * Has a 50% chance to happen when we meet a new peer (either we ask, or we are asked).
     * @param {string} addr address of recipient peer
     */
    const askPeerToReEstablishSession = (addr) => {
        if (window.nkt.userList[addr].receivedOrderToEstablish) {
            return;
        }
        resilientSend({
            msgType: 'sessionEstablishmentOrder',
            msgData:  preKeyBundleToString(
                window.nkt.userList[addr].myNewPreKeyBundle
                || window.nkt.preKeyBundle
            ),
            msgDate: (new Date()).getTime().toString(),
            msgFrom: window.nkt.mySwarm.address(),
            msgBugoutPk: window.nkt.mySwarm.pk,
            msgBugoutEk: window.nkt.mySwarm.ek,
            msgTo: addr
        }, false);
    }

    /**
     * Confirms the signal session establishment went well
     * Asks peer to use signal with us from now on
     * @param {string} addr address of recipient peer
     */
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
    
    /**
     * Fires a 'nktclearmessagereceived' event upon receiving such data
     * @param {Object} e 'nktincomingdata' event
     *  Detects if it is a clear message event to be handed as a
     *  'nktclearmessagereceived' for the upper layer
     * @fires nktclearmessagereceived { e.detail }
     */
    const handleClearMessageForUpperLayer = (e) => {
        if (
            !e.detail.data.msgData
            || !e.detail.data.msgType
            || !e.detail.data.msgFrom
        ) {
            return;
        }
        if (e.detail.data.msgType === 'encrypted') {
            return;
        }
        const msg = e.detail.data;
        if (Object(msg) !== msg) {
            return;
        }
        if (msg.msgType !== 'forUpperLayer') {
            return;
        }
        window.dispatchEvent(
            new CustomEvent('nktclearmessagereceived', { detail: msg.msgData })
        );
    }

    /**
     * Fires a 'nktencryptedmessagereceived' event upon receiving such signal-encrypted data
     * @param {Object} e 'nktincomingdata' event
     *  Detects if it is a signal-encrypted message event to be handed as a
     *  'nktencryptedmessagereceived' for the upper layer
     * @fires nktencryptedmessagereceived { e.detail }
     */
    const handleSignalEncryptedMessageForUpperLayer = (e) => {
        if (
            !e.detail.data.msgData
            || !e.detail.data.msgType
            || !e.detail.data.msgTo
            || !e.detail.data.msgFrom
        ) {
            return;
        }
        if (
            e.detail.data.msgType !== 'encrypted'
            || e.detail.data.msgTo !== window.nkt.mySwarm.address()
            || e.detail.data.msgTo === e.detail.data.msgFrom
        ) {
            return;
        }
        decryptMessageFrom(e.detail.data.msgData, e.detail.data.msgFrom, e.detail.data.msgCipherType).then((plaintext) => {
            try {
                const msg = JSON.parse(plaintext);
                if (msg.msgType !== 'forUpperLayer') {
                    return;
                }
                window.dispatchEvent(
                    new CustomEvent('nktencryptedmessagereceived', { detail: msg.msgData })
                );
            } catch (e) {
                logIfVerbose(e);
            }
        }).catch(err => logIfVerbose(err))
    }

    /**
     * Fires a 'nktencryptedmessagereceived' event upon receiving such bugout-encrypted data
     * @param {Object} e 'nktincomingdata' event
     *  Detects if it is a bugout-encrypted message event to be handed as a
     *  'nktencryptedmessagereceived' for the upper layer
     * @fires nktencryptedmessagereceived { e.detail }
     */
    const handleBugoutEncryptedMessageForUpperLayer = (e) => {
        if (
            !e.detail.data.msgData
            || !e.detail.data.msgType
            || !e.detail.data.msgTo
            || !e.detail.data.msgFrom
        ) {
            return;
        }
        if (
            e.detail.data.msgType !== 'bugoutEncrypted'
            || e.detail.data.msgTo !== window.nkt.mySwarm.address()
            || e.detail.data.msgTo === e.detail.data.msgFrom
        ) {
            return;
        }
        window.dispatchEvent(
            new CustomEvent('nktencryptedmessagereceived', { detail: e.detail.data.msgData })
        );
    }

    /**
     * Handles the preKeyRequest message event
     * @param {Object} e 'nktincomingdata' event
     *  Detects if it is a preKeRequest message event
     */
    const handlePreKeyRequest = (e) => {
        if (e.detail.data.msgType === 'preKeyRequest') {
            if (!e.detail.data.msgFrom) {
                return;
            }
            answerPreKeyRequest(e.detail.data.msgFrom, e.detail.data.msgForAddr);
        }
    }

    /**
     * Handles the preKey (answer) message event
     * @param {Object} e 'nktincomingdata' event
     *  Detects if it is a preKey (answer) message event
     */
    const handlePreKeyAnswer = (e) => {
        if (e.detail.data.msgType === 'preKey') {
            savePreKeyAnswer(e);
        }
    }

    /**
     * Handles the sessionEstablishment message event
     * Tries to decrypt a sessionEstablishment message from a new peer trying to establish a signal session
     * A sessionEstablishment message is the result of a sessionEstablishmentOrder
     * Triggers a restart of the process in case of lack of preKey, after having generated a new one
     * Activates Signal and ask peer to do the same in case of success
     * @param {Object} e 'nktincomingdata' event
     *  Detects if it is a sessionEstablishment message event
     */
    const handleSessionEstablishmentReceived = (e) => {
        if (e.detail.data.msgType === 'sessionEstablishment') {
            if (e.detail.data.msgTo !== window.nkt.mySwarm.address()) {
                return;
            }
            if (window.nkt.userList[e.detail.data.msgFrom].receivedOrderToEstablish) {
                return;
            }
            logIfVerbose('PARSING SESSION ESTABLISHMENT FROM ' + e.detail.data.msgFrom);
            logIfVerbose(e.detail);
            decryptMessageFrom(
                e.detail.data.msgData,
                e.detail.data.msgFrom,
                e.detail.data.msgCipherType
            ).then( (plaintext) => {
                logIfVerbose('decrypted session establishment :');
                logIfVerbose(plaintext);
                if (plaintext === window.nkt.mySwarm.address()) {
                    window.nkt.userList[e.detail.data.msgFrom].sessionEstablished = true;
                    askPeerToUseSignalForMe(e.detail.data.msgFrom);
                    logIfVerbose('ENABLING SIGNAL FOR ' + e.detail.data.msgFrom);
                    window.nkt.userList[e.detail.data.msgFrom].useSignal = true;
                } else {
                    logIfVerbose('BAD SESSION ESTABLISHMENT');
                    logIfVerbose(e.detail);
                    window.nkt.userList[e.detail.data.msgFrom].receivedOrderToEstablish = false;
                    generateNewPreKeyBundle(window.nkt.signalStore, 1, 1).then( (preKeyBundle) => {
                        window.nkt.userList[e.detail.data.msgFrom].preKey = null;
                        window.nkt.userList[e.detail.data.msgFrom].myNewPreKeyBundle = preKeyBundle;
                        startAskingForPreKey(e.detail.data.msgFrom);
                    });
                }
            }).catch( (err) => {
                logIfVerbose('CANNOT DECRYPT SESSION ESTABLISHMENT');
                logIfVerbose(err);
            });
        }
    }

    /**
     * Handles the sessionEstablishmentOrder message event
     * Forces the recording of a given preKey and tries to establish signal session with peer
     * @param {Object} e 'nktincomingdata' event
     *  Detects if it is a sessionEstablishmentOrder message event
     */
    const handleSessionEstablishmentOrder = (e) => {
        if (e.detail.data.msgType === 'sessionEstablishmentOrder') {
            if (e.detail.data.msgTo !== window.nkt.mySwarm.address()) {
                return;
            }
            logIfVerbose('RECEIVED ORDER TO REESTABLISH');
            window.nkt.userList[e.detail.data.msgFrom].receivedOrderToEstablish = true;
            savePreKeyAnswer(e, true);
            startSignalSessionWith(e.detail.data.msgFrom);
        }
    }

    /**
     * Handles signalEnableOrder message event
     * This event is the confirmation that a peer successfully established the signal session we started
     * @param {Object} e 'nktincomingdata' event
     *  Detects if it is a signalEnableOrder message event
     */
    const handleSignalEnableOrder = (e) => {
        if (e.detail.data.msgType === 'signalEnableOrder') {
            if (e.detail.data.msgTo !== window.nkt.mySwarm.address()) {
                return;
            }
            logIfVerbose('ENABLING SIGNAL FOR ' + e.detail.data.msgFrom);
            window.nkt.userList[e.detail.data.msgFrom].useSignal = true;
        }
    }

    /**
     * Generic handler for 'nktincomingdata' events
     * Dispatches to more specific listeners
     * @param {Object} e 'nktincomingdata' event
     */
    const incomingDataHandler = (e) => {
        handleClearMessageForUpperLayer(e);
        handleSignalEncryptedMessageForUpperLayer(e);
        handleBugoutEncryptedMessageForUpperLayer(e);
        handlePreKeyRequest(e);
        handlePreKeyAnswer(e);
        handleSessionEstablishmentReceived(e);
        handleSessionEstablishmentOrder(e);
        handleSignalEnableOrder(e);
    }

    /**
     * Declares internal listeners
     */
    const setListeners = () => {
        window.addEventListener('nktincomingdata', (e) => incomingDataHandler(e));
        window.addEventListener('nktnewpeer', (e) => startAskingForPreKey(e.detail.data.addr));
    }

    /**
     * console.log in verbose mode only (window.nkt.verbose = true)
     * @param {*} msg stringifiable logging message
     */
    const logIfVerbose = (msg) => {
        if (window.nkt.verbose) {
            console.log(msg);
        }
    }

    /**
     * Initialization function
     * Configuration declaration
     * Bugout + Signal initialization
     * Listeners declaration
     */
    window.nkt = window.nkt || {};
    window.nkt.init = (config) => {
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
//                    'stun:global.stun.twilio.com:3478',
//                    'stun:stun.avigora.fr:3478',
                    'stun:stun.1und1.de:3478'
                ]
            },
            {
                "urls": [
                    "turn:numb.viagenie.ca"
                ],
                "username":"webrtc@live.com",
                "credential":"muazkh"
            }
        ];
        if (window.location.href.indexOf('localhost') > -1) {
            window.nkt.trackers.push("ws://localhost:8000");
            window.nkt.websocketEventName = 'nkt';
            window.nkt.verbose = true;
            window.nkt.socketioURL = 'http://localhost:3000';
        } else {
            window.nkt.websocketEventName = 'corev2';
            window.nkt.socketioURL = "wss://" + window.location.hostname;
        }
        if (config) {
            window.nkt = Object.assign(window.nkt, config);
        }
        window.nkt.userList = {};
        window.nkt.sentMessages = [];
        window.nkt.resentMessages = [];
        window.nkt.receivedMessages = [];
        if (window.nkt.websocket) {
            window.nkt.websocket.close();
        }
        window.nkt.websocket = io(window.nkt.socketioURL);
        if (window.nkt.mySwarm) {
            window.nkt.mySwarm.close();
        }
        window.nkt.mySwarm = startWebRTCServer();
        if (!window.nkt.signalStore) {
            signalInit().then((arr) => {
                window.nkt.signalStore = arr[1];
                window.nkt.preKeyBundle = arr[0];
                beginSwarmAddrBroadcast();
            });
        }
        window.nkt.websocket.on(
            window.nkt.websocketEventName,
            handlePingFromWebSocket
        );
        window.nkt.sendEncryptedMessage = sendEncryptedMessage;
        window.nkt.sendClearMessage = sendClearMessage;
        if (!window.nkt.alreadySetListeners) {
            setListeners();
            window.nkt.alreadySetListeners = true;
        }

        sendClearMessage({ping: Math.random.toString()});
    }
    
    //; ( () => {window.nkt.init();})();

})();
