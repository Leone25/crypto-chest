import srpClient from 'secure-remote-password/client.js';
import srpServer from 'secure-remote-password/server.js';

// signup

const username = 'linus@folkdatorn.se';
const password = '$uper$ecure';

const salt = srpClient.generateSalt();
const signupPrivateKey = srpClient.derivePrivateKey(salt, username, password);
const verifier = srpClient.deriveVerifier(signupPrivateKey);

console.log(salt);
console.log(verifier);
// store username (and email), salt and verifier

// login

// ! retrieve salt and verifier from database
const serverEphemeral = srpServer.generateEphemeral(verifier)
console.log(serverEphemeral.public)
// send salt and server ephemeral to client


// ! client
// receive salt and server ephemeral
// generate client ephemeral
const clientEphemeral = srpClient.generateEphemeral()
console.log(clientEphemeral.public)

const privateKey = srpClient.derivePrivateKey(salt, username, password)
const clientSession = srpClient.deriveSession(clientEphemeral.secret, serverEphemeral.public, salt, username, privateKey)
// send client ephemeral and proof to server

console.log(clientSession.key)
console.log(clientSession.proof)

// ! server
// receive client ephemeral and proof
const serverSession = srpServer.deriveSession(serverEphemeral.secret, clientEphemeral.public, salt, username, verifier, clientSession.proof)

console.log(serverSession.key)
console.log(serverSession.proof)

// send proof to client
// ! client
// receive proof
// verify proof
srpClient.verifySession(clientEphemeral.public, clientSession, serverSession.proof)

// done