const mongoose = require('mongoose');
const bcrypt = require('bcrypt');

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
        unique: true,
        lowercase: true
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
        unique: true,
        lowercase: true
      },
  },
  common: {
    refreshToken: String,
    roles: {
      User: {
        type: Number,
        default: 2001    
      },
      Admin: Number
    }
  }
});

module.exports = mongoose.model('User', UserSchema);