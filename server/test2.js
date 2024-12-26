import crypto from 'crypto';
import aes from 'aes-js';


// in this test script we try to encrypt a message and then decrypt it
const message = "asd";
const encryption_key = "86c401df933e26595d2754a26429891fc34da44c2cc4dfdf8c99ae003bd2abf8"; 

console.log(Buffer.from(encryption_key, 'hex'));

const iv = crypto.randomBytes(16);
const cipher = crypto.createCipheriv('aes-256-cbc', Buffer.from(encryption_key, 'hex'), iv);
let encrypted = cipher.update(message, 'utf8', 'hex');
encrypted += cipher.final('hex');

console.log(encrypted);

/*const decipher = crypto.createDecipheriv('aes-256-cbc', Buffer.from(encryption_key, 'hex'), iv);
let decrypted = Buffer.concat([decipher.update(encrypted, 'hex'), decipher.final()]);
console.log(decrypted.toString());*/

const encryptedBytes = aes.utils.hex.toBytes(encrypted);
const aesCtr = new aes.ModeOfOperation.cbc(Buffer.from(encryption_key, 'hex'), iv);
const decryptedBytes = aesCtr.decrypt(encryptedBytes);
const decryptedText = aes.utils.utf8.fromBytes(decryptedBytes);
console.log(decryptedText);