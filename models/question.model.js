const mongoose = require('mongoose');

const QuestionSchema = new mongoose.Schema({
  body: {
    required: true,
    type: String
  },
  poster: {
    required: true,
    type: String
  },
  answered: {
    default: false,
    type: Boolean
  },
  timestamp: {
    type: Date,
    default: Date.now
  }
});


const Questions = mongoose.model('Question', QuestionSchema);

module.exports = Questions;
