const crypto = require('crypto');

function hash(password) {
  const promise = new Promise((resolve, reject) => {
    const salt = crypto.randomBytes(16).toString('hex');
    crypto.pbkdf2(password, salt, 100000, 64, 'sha512', (err, derivedkey) => {
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

    crypto.pbkdf2(password, salt, 100000, 64, 'sha512', (err, derivedkey) => {
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
