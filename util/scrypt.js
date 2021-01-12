const crypto = require('crypto');
const bcrypt = require('bcrypt');
function hash(password) {
  const promise = new Promise((resolve, reject) => {
    const salt = crypto.randomBytes(16).toString('hex');
    crypto.scrypt(password, salt, 64, (err, derivedkey) => {
      if (err) {
        reject(err);
        return;
      }
      resolve(`${salt}.${derivedkey.toString('hex')}`);
    });
  });
  return promise;
}

function compare(hashedPassword, password) {
  const promise = new Promise((resolve, reject) => {
    const [salt, key] = hashedPassword.split('.');

    crypto.scrypt(password, salt, 64, (err, derivedkey) => {
      if (err) {
        reject(err);
        return;
      }
      resolve(key === derivedkey.toString('hex'));
    });
  });
  return promise;
}

module.exports = { hash, compare };
