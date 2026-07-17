// Intentionally vulnerable fixture for codesucks-ai tests. Do not deploy.
const http = require('http');
const url = require('url');
const { exec } = require('child_process');

const server = http.createServer((req, res) => {
  const query = url.parse(req.url, true).query;

  if (query.x) {
    const result = eval(query.x);
    res.end(String(result));
    return;
  }

  if (query.host) {
    exec('ping -c 1 ' + query