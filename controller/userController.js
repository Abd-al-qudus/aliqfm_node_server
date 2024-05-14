const User = require('../models/user.model');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const otpGenerator = require('otp-generator');
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


const generateOTP = async (req, res) => {
  const OTP = await otpGenerator.generate(8, { lowerCaseAlphabets: false, upperCaseAlphabets: true, specialChars: false });
  req.app.locals.OTP = OTP;
  return res.status(201).json({ OTP });
}


const verifyOTP = async (req, res) => {
  const { email, OTP } = req.query;
  if (!OTP || !email) return res.sendStatus(400);
  if (String(OTP) !== String(req.app.locals.OTP)) return res.sendStatus(400);
  try {
    const user = await User.findOne({ 'local.email': email }).exec();
    if (!user) return res.status(404).json({ 'error': 'user does not exist' });
    if (user.common.verified) {
      req.app.locals.OTP = null;
      req.app.locals.reset = true;
      return res.status(400).json({ 'message': 'user already verified' });
    }
    req.app.locals.OTP = null;
    req.app.locals.reset = true;
    user.common.verified = true;
    await user.save();
    return res.status(200).json({ 'message': 'OTP verified successfully' });
  } catch (error) {
    return res.status(500).json({ error });
  }
}


const resetPassword = async (req, res) => {
  if (!req.app.locals.reset) return res.status(404).json({ 'error': 'auth session expired' });
  const { email, newPassword} = req.body;
  if (!newPassword || !email) return res.status(400).json({ 'error': 'missing email or password' });
  if (typeof email !== "string") return res.status(400).json({error: "email must be a string"});
  if (typeof newPassword !== "string") return res.status(400).json({error: "password must be a string"});
  try {
    const user = await User.findOne({ 'local.email': email }).exec();
    if (!user) return res.status(404).json({ 'error': 'user does not exist' });
      const newpwd = await bcrypt.hash(newPassword, 10);
      user.local.password = newpwd;
      await user.save();
      req.app.locals.reset = false;
      return res.status(200).json({ 'message': 'user password changed' });
  } catch (error) {
    return res.status(500).json({ error });
  }
}


const resetSession = async (req, res) => {
  if (req.app.locals.reset){
    req.app.locals.reset = false;
    return res.status(201).json({ 'message': 'session reseted' });
  }
  return res.status(440).json({ 'error': 'sesssion expired' });
}


module.exports = { register, 
                    login, 
                    logout, 
                    refreshAccessToken, 
                    generateOTP, 
                    verifyOTP, 
                    resetPassword,
                    resetSession };
