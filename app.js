var url = require("url");
var fs = require('fs');
var resources = ['/bugout-signal-test.js', '/bugout.min.js', '/libsignal-protocol.js'];
function onRequest(req, res) {
  var pathname = url.parse(req.url).pathname;
  var id = resources.indexOf(pathname);
  var file = id === -1 ? 'index.html' : resources[id];
  fs.readFile(__dirname + '/' + file, function (err, data) {
    if (err) { res.writeHead(500); return res.end('Error loading resource.'); }
    res.writeHead(200);
    res.end(data);
  });
}
var http = require("http").createServer(onRequest);
var io = require('socket.io')(http);
io.on('connection', (socket) => {
  socket.on('nkt', (data) => {
    socket.broadcast.emit('nkt', data);
  });
});
http.listen(3000);
console.log("Server has started on port 3000.");