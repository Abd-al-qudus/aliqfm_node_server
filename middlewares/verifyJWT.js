const jwt = require('jsonwebtoken');
const dotenv = require('dotenv');
const User = require('../models/user.model');


dotenv.config();


const verifyJsonWebToken = (req, res, next) => {
  const token_header = req.headers['authorization'] || req.headers['Authorization'] || req.session.accessToken;
  if (!token_header) return res.sendStatus(401);
  const accessToken = token_header.split(' ')[1];
  if (!accessToken) return res.sendStatus(403);
  jwt.verify(
    accessToken,
    process.env.ACCESS_TOKEN,
    async (error, decoded) => {
      if (error) return res.sendStatus(403);
      req.user = { email: decoded.email, id: decoded.sub };
      const user = await User.findOne({
        $or: [
          { 'local.email': decoded.email },
          { 'google.email': decoded.email }
        ]
      }).exec();
      if (!user.common.verified) return res.sendStatus(401);
      next();
    }
  );
}


module.exports = verifyJsonWebToken;
