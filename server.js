const express = require('express');
const dotenv = require('dotenv');
const cors = require('cors');
const {requestLogger, errorLogger } = require('./middlewares/eventLogger');
const router = require('./routes/index');

dotenv.config()

const port = process.env.PORT || 3500

server = express();
server.use(requestLogger);
server.use(cors());
server.use(router);

server.use(errorLogger);
server.listen(port, ()=> console.log(`server running on port ${port}`));