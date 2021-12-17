const { Schema, model } = require('mongoose');

// TODO: Please make sure you edit the user model to whatever makes sense in this case
const userSchema = new Schema({
  username: {
    type: String,
    unique: true,
    required: true
  },
  password: {
    type: String,
    required: true
  },
  email: {
    type: String,
    required: [true, 'Email es required.'],
    unique: true,
    lowercase: true,
    trim: true
  }
});

module.exports = model('User', userSchema);
