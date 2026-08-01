const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const bundlePath = path.resolve(__dirname, '../public/bundle.js');
const signaturePath = path.resolve(__dirname, '../public/bundle.js.sig');

const data = fs.readFileSync(bundlePath);
const signature = crypto.createHash('sha256').update(data).digest('base64');
fs.writeFileSync(signaturePath, signature);
console.log('Signature generated:', signaturePath);
