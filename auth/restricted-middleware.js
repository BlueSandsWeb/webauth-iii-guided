const bcrypt = require('bcryptjs');
// bring in JWT
const jwt = require('jsonwebtoken');
const secrets = require('../api/secrets.js');

module.exports = (req, res, next) => {
  // STEP 2.1: read token from authorization
  const token = req.headers.authorization;

  // STEP 2.2: Check for token
  if (token) {
    jwt.verify(token, secrets.jwtSecret, (err, decodedToken) => {
      if (err) { // the token is not valid
        res.status(401).json({ message: 'Invalid Credentials' });
      } else { // all good
        // req.decodedJwt = decodedToken;  // makes the token info available to the rest of the application
        next();
      }
    }) // have secret on the .env as a variable when in production
  } else {
    res.status(401).json({ message: 'No token provided' }); // no token, no passage
  }
};
