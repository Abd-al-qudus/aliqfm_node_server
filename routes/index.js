const express = require('express');
const verifyJWT = require('../middlewares/verifyJWT');
const { register, login, logout, refreshAccessToken } = require('../controller/userController');


const router = express.Router();

router.get('/', verifyJWT, (req, res) => {
  return res.status(200).json({
    status: 200,
    message: "success"
  })
})

router.post('/api/auth/create', register);
router.post('/api/auth', login);
router.get('/api/auth', logout);
router.get('/api/auth/refresh', refreshAccessToken);


module.exports = router;