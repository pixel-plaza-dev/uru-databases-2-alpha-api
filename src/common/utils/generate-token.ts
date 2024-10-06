// Generate random token
const token = require('crypto').randomBytes(64).toString('hex');
console.log(token);
