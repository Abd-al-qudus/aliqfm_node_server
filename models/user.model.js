const mongoose = require('mongoose');


const UserSchema = new mongoose.Schema({
  method: {
    type: String,
    enum: ['local', 'google'],
    required: true
  },
  local: {
    username: {
        type: String,
        lowercase: true
      },
      email: {
        type: String,
        lowercase: true,
      },
    password: String
  },
  google: {
    username: {
        type: String,
        lowercase: true
      },
      email: {
        type: String,
        lowercase: true,
      },
  },
  common: {
    refreshToken: String,
    verified: {
      type: Boolean,
      default: false
    },
    mobile: String,
    firstName: String,
    lastName: String,
    roles: {
      User: {
        type: Number,
        default: 2001    
      },
      Admin: Number
    }
  }
});


const user = mongoose.model('User', UserSchema)

module.exports = user;