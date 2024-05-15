const User = require('../models/user.model');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const otpGenerator = require('otp-generator');
const nodemailer = require('nodemailer');
const mailGenerator = require('mailgen');
const dotenv = require('dotenv');
const { generateJWTAccess, generateJWTRefresh } = require('../utils/generateJWT');


dotenv.config();

const register = async (req, res) => {
  const { email, password } = req.body;
  if (typeof email !== "string") return res.status(400).json({error: "email must be a string"});
  if (typeof password !== "string") return res.status(400).json({error: "password must be a string"});
  if (!email) return res.status(400).json({error: "email is empty"});
  if (!password) return res.status(400).json({error: "password is empty"});
  try {
    const existingUser = await User.findOne({
      $or: [
        { "local.email": email },
        { "google.email": email }
      ]
    }).exec();
    if (existingUser) {
      if (existingUser.common.verified) return res.status(409).json({ error: "user already exist" });
      return res.redirect(`/api/auth/otp?email=${email}`);
    }
    const hashed_password = await bcrypt.hash(password, 10);
    const newUser = User({
      method: 'local',
      local: {
        email: email,
        password: hashed_password
      }
    });
    await newUser.save();
    return res.redirect(`/api/auth/otp?email=${email}`);
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
  const smtpConfig = {
    host: process.env.SMTP_HOST,
    port: process.env.SMTP_PORT,
    secure: false,
    auth: {
        user: process.env.SMTP_EMAIL,
        pass: process.env.SMTP_PASSWORD
    }
  }
  const transporter = nodemailer.createTransport(smtpConfig);
  const mailGen = new mailGenerator({
  theme: "default",
  product: {
    name: "MailGen",
    link: "https://mailgen.js"
  }
  });
  try {
    const email = req.user ? req.user.email : req.query.email;
    const mail = {
      body: {
      name: email,
      intro: ['Welcome to Al-Iqmah!!!', `your OTP is ${OTP}`],
      outro: "This email is automatically generated upon user verification."
      }
    }
    const body = await mailGen.generate(mail);
    const message = {
      from: process.env.SMTP_EMAIL,
      to: email,
      subject: "Al-Iqmah OTP Generator",
      html: body
    }
    await transporter.sendMail(message);
    return res.status(200).json({ "message": "check your email for OTP" });
  } catch (error) {
    return res.status(500).json({ 'error': 'could not get OTP for verification' });
  }
  // return res.redirect(`/api/auth/send-email?subject=verification`);
}


const verifyOTP = async (req, res) => {
  const { email, OTP } = req.query;
  if (!OTP || !email) return res.sendStatus(400);
  if (String(OTP) !== String(req.app.locals.OTP)) return res.sendStatus(400);
  try {
    const user = await User.findOne({ 
      $or: [
        { 'local.email': email },
        { 'google.email': email }
      ]
    }).exec();
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
