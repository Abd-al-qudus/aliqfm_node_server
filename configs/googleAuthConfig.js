const Passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const dotenv = require('dotenv');
const User = require('../models/user.model');
const { generateJWTAccess, generateJWTRefresh } = require('../utils/generateJWT');


dotenv.config();


const passport = Passport;
passport.use(new GoogleStrategy({
  clientID: process.env.CLIENT_ID,
  clientSecret: process.env.SECRET_ID,
  callbackURL: process.env.REDIRECT_URL,
  scope: ['email', 'profile'],
  }, async (_, __, profile, done) => {
    try {
      const user = await User.findOne({
         $or: [
          { "google.email": profile._json.email },
          { "local.email": profile._json.email }
         ]
       });
      if (user){
        // if (!user.common.verified) return done(null, null);
        accessToken = generateJWTAccess({ email: profile._json.email, id: profile._json.sub, duration: "1m"});
        refreshToken = generateJWTRefresh({ email: profile._json.email, id: profile._json.sub, duration: "1d" });
        user.common.refreshToken = refreshToken;
        await user.save();
        const data = {email: profile._json.email, id: profile._json.sub, verified: user.common.verified, refreshToken, accessToken};
        return done(null, data);
      }
      accessToken = generateJWTAccess({ email: profile._json.email, id: profile._json.sub, duration: "1m"});
      refreshToken = generateJWTRefresh({ email: profile._json.email, id: profile._json.sub, duration: "1d" });
      const newUser = new User({
        method: 'google',
        google: {
          username: profile._json.name,
          email: profile._json.email,
        },
        common: {
          refreshToken: refreshToken
        }
      });
      await newUser.save();
      const data = {email: profile._json.email, id: profile._json.sub, verified: false, refreshToken, accessToken};
      return done(null, data);
    } catch (error) {
      return done(error, profile._json);
    }
}));


passport.serializeUser(function (user, cb) {
    cb(null, user);
});
passport.deserializeUser(function (user, cb){
    cb(null, user);
});

module.exports = passport;
