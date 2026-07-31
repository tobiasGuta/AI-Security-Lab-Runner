const http = require('http');

const PORT = 8080;

const server = http.createServer((req, res) => {
  if (req.url === '/health') {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ status: 'ok', service: 'web-front' }));
  } else {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ message: 'Multi-container web frontend active' }));
  }
});

server.listen(PORT, '0.0.0.0', () => {
  console.log(`Web frontend running on port ${PORT}`);
});
