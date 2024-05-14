const express = require('express');
const emailRegistration = require('../configs/emailSMTPConfig');
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
router.get('/api/auth/verify-otp', verifyOTP);
router.put('/api/auth/reset-password',resetPassword);
router.get('/api/auth/reset-session',resetSession);
router.post('/api/auth/email', emailRegistration);


module.exports = router;