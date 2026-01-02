import http from 'node:http';
http
  .createServer((req, res) => {
    res.writeHead(200, { 'Content-Length': 5, Connection: 'close' });
    res.end('hello');
  })
  .listen(3001);
