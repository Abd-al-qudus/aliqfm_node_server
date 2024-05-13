const express = require('express');
const dotenv = require('dotenv');
const cors = require('cors');
const {requestLogger, errorLogger } = require('./middlewares/eventLogger');
const router = require('./routes/index');
const mongoose = require('mongoose');
const bodyparser = require('body-parser');
const cookieParser = require('cookie-parser');
const connectDB = require('./configs/databaseConfig');


dotenv.config()

const port = process.env.PORT || 3500
server = express();
server.use(requestLogger);
server.use(cookieParser());
server.use(cors());
server.use(express.json());
server.use(bodyparser.urlencoded({
  extended: true
}));
connectDB();
server.use(router);

server.use(errorLogger);
mongoose.connection.once('open', () => {
  console.log('connected to ALIQFM server');
  server.listen(port, ()=> console.log(`server running on PORT ${port}`));
});
