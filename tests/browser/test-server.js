const http = require('http');
const fs = require('fs');
const path = require('path');

const PORT = process.env.TEST_PORT || 3000;
const SERVE_DIR = process.env.SERVE_DIR || path.resolve(__dirname, 'wasm-out');

const MIME_TYPES = {
  '.html': 'text/html',
  '.js': 'application/javascript',
  '.mjs': 'application/javascript',
  '.wasm': 'application/wasm',
  '.css': 'text/css',
  '.json': 'application/json',
};

const TEST_HTML = path.resolve(__dirname, 'test-main.html');

const server = http.createServer((req, res) => {
  const filePath = req.url === '/' ? TEST_HTML : path.join(SERVE_DIR, req.url);
  const ext = path.extname(filePath);
  const contentType = MIME_TYPES[ext] || 'application/octet-stream';

  res.setHeader('Cross-Origin-Opener-Policy', 'same-origin');
  res.setHeader('Cross-Origin-Embedder-Policy', 'credentialless');

  fs.readFile(filePath, (err, data) => {
    if (err) {
      res.writeHead(404);
      res.end('Not Found');
      return;
    }
    res.writeHead(200, { 'Content-Type': contentType });
    res.end(data);
  });
});

server.listen(PORT, () => {
  console.log(`Test server running at http://localhost:${PORT} serving ${SERVE_DIR}`);
});
