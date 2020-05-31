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
# Go take a coffee (10 sec - crypto is fast BUT session establishment is meh) or open browser console
# Type a message, clic 'send' (use mouse)
# See wow message on other tab amazing
# Hey kill app.js now, we don't need this loser
# Try sending another message
# See wow it worked again amazing
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

## Acknowledgements

```
https://github.com/signalapp/libsignal-protocol-javascript
https://github.com/chr15m/bugout
https://github.com/webtorrent/bittorrent-tracker
https://github.com/socketio/socket.io
```