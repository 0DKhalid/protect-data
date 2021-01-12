const express = require('express');
const db = require('diskdb');
const bcrypt = require('bcrypt');
const aes256cbc = require('./util/aes256cbc');

db.connect('./db', ['Users']);

const app = express();

app.use(express.json());

// get all users from users collection
app.get('/users', (req, res) => {
  const users = db.Users.find();

  res.json(users);
});

//create new user
app.post('/signup', async (req, res) => {
  const { email, password, name, sensitiveData } = req.body;

  const userExisit = db.Users.findOne({ email: email });
  if (userExisit) {
    res.status(403).json({
      success: false,
      message: 'user already exisit try with another email'
    });

    return;
  }

  try {
    const hashedPass = await bcrypt.hash(password, 12);
    const encryptedData = await aes256cbc.encrypt(sensitiveData);
    const user = db.Users.save({
      email,
      hashedPass,
      name,
      sensitiveData: encryptedData
    });

    res.status(201).json({ success: true, user });
  } catch (err) {
    res.status(500).json({ err: err });
  }
});

// login user
app.post('/login', async (req, res) => {
  const { email, password } = req.body;
  const userExisit = db.Users.findOne({ email });

  if (!userExisit) {
    res
      .status(401)
      .json({ success: false, message: 'email or password incorrect' });
    return;
  }

  const passwordValid = await bcrypt.compare(password, userExisit.hashedPass);
  if (!passwordValid) {
    res
      .status(401)
      .json({ success: false, message: 'email or password incorrect' });
    return;
  }

  const decryptedData = await aes256cbc.decrypt(userExisit.sensitiveData);

  userExisit.sensitiveData = decryptedData;

  res.status(200).json({
    success: true,
    message: 'login success',
    user: userExisit
  });
});

const PORT = 3000;
app.listen(PORT, () => console.log(`Server is running on port ${PORT}`));
