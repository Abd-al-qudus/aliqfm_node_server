const User = require('../models/user.model');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { generateJWTAccess, generateJWTRefresh } = require('../utils/generateJWT');


const register = async (req, res) => {
  const { email, password } = req.body;
  if (typeof email !== "string") return res.status(400).json({error: "email must be a string"});
  if (typeof password !== "string") return res.status(400).json({error: "password must be a string"});
  if (!email) return res.status(400).json({error: "email is empty"});
  if (!password) return res.status(400).json({error: "password is empty"});
  try {
    const existingUser = await User.findOne({ "local.email": email }).exec();
    if (existingUser) return res.status(409).json({ error: "user already exist" });
    const hashed_password = await bcrypt.hash(password, 10);
    const newUser = User({
      method: 'local',
      local: {
        email: email,
        password: hashed_password
      }
    });
    await newUser.save();
    return res.status(201).json({ status: 201, message: "user created"});
  } catch(error){
    return res.status(500).json({
      status: 500, 
      message: "creation failed", 
      error: error 
    });
  }
}


const login = async (req, res) => {
  const { email, password } = req.body;
  if (typeof email !== "string") return res.status(400).json({error: "email must be a string"});
  if (typeof password !== "string") return res.status(400).json({error: "password must be a string"});
  if (!email) return res.status(400).json({error: "email is empty"});
  if (!password) return res.status(400).json({error: "password is empty"});
  try {
    const user = await User.findOne({ 'local.email': email }).exec();
    if (!user) return res.sendStatus(403);
    const verified_pwd = await bcrypt.compare(password, user.local.password);
    if (!verified_pwd) return res.sendStatus(403)
    const accessToken = generateJWTAccess({ email: user.local.email, id: user._id, duration: '1m' });
    const refreshToken = generateJWTRefresh({ email: user.local.email, id: user._id, duration: '1d' });
    user.common.refreshToken = refreshToken;
    await user.save();
    res.cookie('jwt', refreshToken, { httpOnly: true, maxAge: 24 * 1000 * 3600, sameSite: 'None' });
    return res.status(200).json({
      status: 200,
      email: user.email,
      accessToken: accessToken
    });
  } catch(error){
    return res.status(500).json({
      status: 500,
      error: error
    });
  }
}


const logout = async (req, res) => {
  const cookies = req.cookies;
  if (!cookies?.jwt) return res.sendStatus(401);
  const refreshToken = cookies.jwt;
  try {
    const user = await User.findOne({ 'common.refreshToken': refreshToken }).exec();
    if (!user) {
      res.clearCookie('jwt', { httpOnly: true });
      return res.sendStatus(403);
    }
    user.common.refreshToken = '';
    await user.save();
    res.clearCookie('jwt', { httpOnly: true });
    return res.sendStatus(204)
  } catch (error) {
    return res.status(500).json({
      status: 500,
      error: error
    });
  }
}


const refreshAccessToken = async (req, res) => {
  const cookies = req.cookies;
  if (!cookies?.jwt) return res.sendStatus(401);
  const refreshToken = cookies.jwt;
  try {
    const user = await User.findOne({ 'common.refreshToken': refreshToken }).exec();
    if (!user) return res.sendStatus(403);
    jwt.verify(
      refreshToken,
      process.env.REFRESH_TOKEN,
      (err, decoded) => {
        console.log(decoded);
          if (err || user.local.email !== decoded.email) {
            return res.sendStatus(403);
          }
          const accessToken = generateJWTAccess({ email: decoded.email, id: decoded._id, duration: '1m' });
          return res.json({ accessToken });
      }
    );
  } catch (error) {
    return res.status(500).json({
      status: 500,
      error: error
    });
  }
}

module.exports = { register, login, logout, refreshAccessToken };
