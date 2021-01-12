const crypto = require('crypto');
const util = require('util');

const KEY = 'aO@UvvAz9mdIYHHcr6WJEoeGxq!E*aJY';

const alg = 'aes-256-cbc';

const pbkdf2 = util.promisify(crypto.pbkdf2);

async function gKey(salt) {
  return await pbkdf2(KEY, salt, 100000, 32, 'sha512');
}

async function encrypt(data) {
  const iv = crypto.randomBytes(16);
  const salt = crypto.randomBytes(16);

  const key = await gKey(salt);

  const cipher = crypto.createCipheriv(alg, key, iv);

  let encryptedData = cipher.update(data);

  encryptedData = Buffer.concat([encryptedData, cipher.final()]);

  return (
    iv.toString('hex') + encryptedData.toString('hex') + salt.toString('hex')
  );
}

function sliceCipherText(cText) {
  const iv = cText.slice(0, 32);
  const salt = cText.slice(-32);
  const encryptedData = cText.slice(32, cText.length - 32);

  return [
    Buffer.from(iv, 'hex'),
    Buffer.from(encryptedData, 'hex'),
    Buffer.from(salt, 'hex')
  ];
}

async function decrypt(cipherText) {
  const [iv, encryptedData, salt] = sliceCipherText(cipherText);

  const key = await gKey(salt);

  const decipher = crypto.createDecipheriv(alg, key, iv);
  let decryptedData = decipher.update(encryptedData);

  decryptedData = Buffer.concat([decryptedData, decipher.final()]);

  return decryptedData.toString();
}

module.exports = { encrypt, decrypt };
