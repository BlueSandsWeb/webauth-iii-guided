const router = require('express').Router();
const bcrypt = require('bcryptjs');
// step 1: require json web token ***************************************
const jwt = require('jsonwebtoken');

// STEP 2.3 get secret and pass to function below
const secrets = require('../api/secrets.js');

const Users = require('../users/users-model.js');

// for endpoints beginning with /api/auth
router.post('/register', (req, res) => {
  let user = req.body;
  const hash = bcrypt.hashSync(user.password, 10); // 2 ^ n
  user.password = hash;

  Users.add(user)
    .then(saved => {
      res.status(201).json(saved);
    })
    .catch(error => {
      res.status(500).json(error);
    });
});

router.post('/login', (req, res) => {
  let { username, password } = req.body;

  Users.findBy({ username })
    .first()
    .then(user => {
      if (user && bcrypt.compareSync(password, user.password)) {
        // STEP 1.1 - Create Token **************************************************
        const token = generateToken(user);

        res.status(200).json({
          message: `Welcome ${user.username}!`,
          token // STEP 1.4: send token as well ****************************************
        });
      } else {
        res.status(401).json({ message: 'Invalid Credentials' });
      }
    })
    .catch(error => {
      res.status(500).json(error);
    });
});

// STEP 1.3 - create generate token function ********************************************
function generateToken(user) {
  const payload = {
    subject: user.id,
    username: user.username
  };
  const secret = secrets.jwtSecret; // Get secret from .env file.  Maybe make a third file to handle grabbing secrets for you
  const options = {
    expiresIn: '1d',     // 1 day (check docs)
  }
  return jwt.sign(payload, secret, options);
}

module.exports = router;
