const express = require('express');
const passport = require('../configs/googleAuthConfig');
const emailRegistration = require('../configs/emailSMTPConfig');
const User = require('../models/user.model');
const verifyJsonWebToken = require('../middlewares/verifyJWT');
const { register, 
        login, 
        logout, 
        refreshAccessToken, 
        generateOTP, 
        verifyOTP, 
        resetPassword,
        resetSession } = require('../controller/userController');


const router = express.Router();

router.get('/', verifyJsonWebToken, (req, res) => {
  return res.status(200).json({
    status: 200,
    message: "success"
  })
})

router.post('/api/auth/create', register);
router.route('/api/auth')
            .post(login)
            .get(logout);
            
router.get('/api/auth/refresh', refreshAccessToken);
router.get('/api/auth/otp', generateOTP);
router.post('/api/auth/verify-otp', verifyOTP);
router.put('/api/auth/reset-password',resetPassword);
router.get('/api/auth/reset-session',resetSession);
router.post('/api/auth/send-email', emailRegistration);


router.get('/api/auth/google', passport.authenticate('google', {
  accessType: 'offline',
  approvalPrompt: 'force',
}), (req, res) => {
  res.sendStatus(200);
});


router.get('/auth/google/callback', passport.authenticate('google', {
  successRedirect: '/api/auth/google/redirect/done',
  failureRedirect: '/api/auth/google/failure'
}), (req, res) => {
  res.sendStatus(200);
});
router.get('/api/auth/google/failure', (req, res) => {
  return res.status(500).json({ message: 'something went wrong' });
});


router.get('/api/auth/google/redirect/done', async (req, res) => {
  try {
      const accessToken = req.user.accessToken;
      const refreshToken = req.user.refreshToken;
      res.cookie('jwt', refreshToken, { httpOnly: true, maxAge: 24 * 3600 * 1000 , sameSite: 'None', secured: true });
      req.session.accessToken = `jwt ${accessToken}`;
      if (!req.user.verified) return res.redirect('/api/auth/otp');
      return res.redirect('/');
  } catch (error) {
      return res.sendStatus(400);
  }
});


module.exports = router;