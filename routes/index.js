const express = require('express');


const router = express.Router();

router.get('/auth', (req, res) => {
  return res.send('auth get success');
});

module.exports = router;