const jwt = require('jsonwebtoken');
const dotenv = require('dotenv');

dotenv.config();

const generateJWTAccess = (user) => {
  const payload = {
    sub: user.id,
    email: user.email
  };
  return jwt.sign(
    payload,
    process.env.ACCESS_TOKEN,
    { expiresIn: user.duration }
  )
}


const generateJWTRefresh = (user) => {
  const payload = {
    sub: user.id,
    email: user.email
  };
  return jwt.sign(
    payload,
    process.env.REFRESH_TOKEN,
    { expiresIn: user.duration }
  )
}

module.exports = { generateJWTAccess, generateJWTRefresh };
