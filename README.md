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
# - window.nkt.userList (each user has a unique addr and a window.nkt.userList[addr].dontSendTo flag)
# - local (self) addr is window.nkt.mySwarm.address()
# - events with misleading names like 'nktnewpeer' (may fire several times), 'nktincomingdata', 'nktoutgoingdata' 
# - better events : nktmessagereceived, nktsendingmessage ... plugin can define events too, like nktdisplaymessage
```

## Concept

- 1 nkt browser tab = 1 peer
- when available, peers advertise themselves through app.js websocket
- app.js be the lightest (no express)
- [TODO] manual connection /connect [peerAddr-as-listed-on-trackers]
- each peer has a swarm of known users, there is 1 swarm per user
- some peers in the swarm are reachable webrtc peers (joinable on websocket server unreachable)
- messages are send through webrtc and websocket and deduplicated
- when a peer is added to the swarm, a signal session is established for secure messaging
- swarms try to maximize reach by propagating to their swarm (1) signal public keys and (2) known peer addresses
- websocket, webrtc and signal connection/session establishment should be resilient to poor network
- PRE-PRE-ALPHA VERY SLOW AND BUGGY TOUCH WITH A STICK ONLY, browser entrypoint is `bugout-signal-test.js`
- MERGE WITH NKT IN PROGRESS

## Acknowledgements

```
https://github.com/signalapp/libsignal-protocol-javascript
https://github.com/chr15m/bugout
https://github.com/webtorrent/bittorrent-tracker
https://github.com/socketio/socket.io
```
