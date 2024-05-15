const express = require('express');
const dotenv = require('dotenv');
const cors = require('cors');
const {requestLogger, errorLogger } = require('./middlewares/eventLogger');
const router = require('./routes/index');
const mongoose = require('mongoose');
const bodyparser = require('body-parser');
const cookieParser = require('cookie-parser');
const connectDB = require('./configs/databaseConfig');
const session = require('express-session');
const passport = require('passport');


dotenv.config()

const port = process.env.PORT || 3500
server = express();

server.use(session({
  resave: false,
  saveUninitialized: true,
  secret: process.env.SECRET_ID
}));
server.use(passport.initialize());
server.use(passport.session());

server.use(requestLogger);
server.use(express.json());
server.use(cookieParser());
server.use(cors());
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
