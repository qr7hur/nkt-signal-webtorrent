# nkt-signal-webtorrent

```
# Start private tracker (public tracker can also be used)
cd tracker
npm install
./node_modules/.bin/bittorrent-tracker --ws

cd ..

# Start server
npm install
node app.js

# Visit http://localhost:3000 on tab 1, tab2
# Login, type a message, send
# See message on other tab
# Hey kill app.js now, we don't need this loser
# Try sending another message
# Message should be received through webrtc

# High level apis (TODO better) :
# - window.nkt.sendEncryptedMessage() to send high level message (for human or bot)
# - window.nkt.userList 
# -- (each user has a unique addr, window.nkt.userList[addr].(dontSendTo | isUnreachable) writable flags)
# - local (self) addr is window.nkt.mySwarm.address()
# - low level events with misleading names like
# -- 'nktnewpeer' (may fire several times), 'nktincomingdata', 'nktoutgoingdata' 
# - better events : nktencryptedmessagereceived, nktclearmessagereceived, nktsendingmessage
# - nktwebrtcseen, nktwebrtcleft
# -- ... plugin can define events too, like nktdisplaymessage
```

## Concept

- 1 nkt browser tab = 1 peer (webtorrent = bittorrent over webrtc)
- when available, peers use app.js websocket for sig and data
- peers also announce themselves on various webtorrent trackers
- app.js should be as lightweight as possible (no express, pg ...)
- each peer belongs to the nkt swarm of known users
- some peers in the swarm are reachable webrtc peers (joinable when websocket data is unreachable)
- all messages are sent through webrtc and websocket and deduplicated
- peers which are able to use both webrtc and websocket will be used as a bridge between peers which only have one option
- when a peer is added to the swarm, a signal session is established with it for secure messaging (libsignal)
- websocket, webrtc and signal connection/session establishment should be resilient to poor network
- browser entrypoint is `bugout-signal-test.js`
- interface with nkt by providing a dedicated socket_test.js wrapper

## Acknowledgements

```
https://github.com/signalapp/libsignal-protocol-javascript
https://github.com/chr15m/bugout
https://github.com/webtorrent/bittorrent-tracker
https://github.com/socketio/socket.io

Additional front-end dependencies : 
bs58, bencode, nacl

TODO : package front-end (libsignal+bugout+socket.io+bs58+bencode+nacl+custom:bugout-signal-test.js)
```
