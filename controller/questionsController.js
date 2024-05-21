const Questions = require('../models/question.model.js');


const getQuestions = async (req, res) => {
  try {
    const poster = req.query.poster;
    if (!poster) {
      const allQuestions = await Questions.find({}).exec();
      return res.status(200).json({ allQuestions });
    }
    if (typeof poster !== "string") return res.status(400).json({ 'error': 'poster id must be a string' });
    const userQuestions = await Questions.find({ "poster": poster }).exec();
    return res.status(200).json({ userQuestions });
  } catch (error) {
    return res.status(500).json({ error });
  }
}


const postQuestion = async (req, res) => {
  try {
    const { body, poster } = req.body;
    if (!poster || !body) return res.status(400).json({ 'error': 'missing request body' });
    if (typeof poster !== "string" || typeof body !== "string") return res.status(400).json({ 'error': 'invalid request body' });
    const newQuestion = new Questions({
      body: body,
      poster: poster
    });
    await newQuestion.save();
    return res.status(201).json({
      'statusCode': 201,
      'message': 'question created',
      'questionId': String(newQuestion._id),
      'created by': poster,
      'body': body
    });
  } catch (error) {
    return res.status(500).json({ error });
  }
}


const editQuestion = async (req, res) => {
  try {
    const { body, id, answered } = req.body;
    if (!body) {
      if (answered && id) {
        if (typeof id !== "string" || typeof answered !== "boolean") return res.status(400).json({ 'error': 'missing request parameters' });
        const question = await Questions.findOne({ _id: id });
        question.answered = answered;
        await question.save();
        return res.sendStatus(200);
      }
      return res.status(400).json({ 'error': 'missing request body' });
    }
    if (typeof body !== "string" || typeof id !== "string") return res.status(400).json({ 'error': 'invalid request body' });
    const question = await Questions.findOne({ _id: id });
    if (!question) return res.status(400).json({ 'error': 'question does not exist' });
    question.body = body;
    await question.save();
    return res.status(201).json({
      'statusCode': 201,
      'message': 'question edited',
      'id': id,
      'body': body
    });
  } catch (error) {
    return res.status(500).json({ error });
  }
}


const getQuestion = async (req, res) => {
  try {
    const id = req.query.id;
    if (!id) return res.status(400).json({ 'error': 'missing request id' });
    if (typeof id !== "string") return res.status(400).json({ 'error': 'invalid request body' });
    const question = await Questions.findOne({ _id: id }).exec();
    return res.status(200).json({ question });
  } catch (error) {
    return res.status(500).json({ error });
  }
}


const deleteQuestion = async (req, res) => {
  try {
    const id = req.query.id;
    if (!id) return res.status(400).json({ 'error': 'missing id' });
    if (typeof id !== "string") return res.status(400).json({ 'error': 'invalid request body' });
    await Questions.deleteOne({ _id: id });
    return res.sendStatus(204);
  } catch (error) {
    return res.status(500).json({ error });
  }
}


module.exports = { 
    getQuestions, 
    getQuestion, 
    editQuestion, 
    postQuestion, 
    deleteQuestion }
