const fs = require('fs');
const path = require('path');
const {format} = require('date-fns');
const fsPromises = require('fs').promises;
const parser = require('ua-parser-js');
const geoip = require('geoip-lite');




const logger = async (message, logName) => {
  const date = `${format(new Date(), 'yyyMMdd\tHH:mm:ss')}`;
  const logMessage = `${date}\t${message}`;
  try {
    if (!fs.existsSync(path.join(__dirname, '..', 'logs'))){
      await fsPromises.mkdir(path.join(__dirname, '..', 'logs'));
    }
    await fsPromises.appendFile(path.join(__dirname, '..', 'logs', logName), logMessage);
  } catch(error){
    console.log(error);
  }
}

const requestLogger = async (req, res, next) => {
  const result = parser(req.headers['user-agent']);
  const ipData = req.ip;
  const ip = ipData.split(":")[ipData.split(':').length - 1];
  logger(`${ip}\t${result.os.name}\t${result.browser.name}\t${req.method}\t${req.headers.origin}\t${req.url}\n`, 'request_logs.txt');
  next();
}

const errorLogger = async (err, req, res, next) => {
  logger(`${err.name}:\t${err.message}\n`, 'error_logs.txt');
  res.status(500).send(err.message);
}


module.exports = { requestLogger, errorLogger }