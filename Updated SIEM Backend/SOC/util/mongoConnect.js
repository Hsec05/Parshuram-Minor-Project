const mongoose = require('mongoose');
const { MONGO_URI } = process.env;

async function connectDB() {
  if (!MONGO_URI) throw new Error('MONGO_URI not set in .env');
  await mongoose.connect(MONGO_URI);
  console.log('Connected to MongoDB');
}

module.exports = connectDB;