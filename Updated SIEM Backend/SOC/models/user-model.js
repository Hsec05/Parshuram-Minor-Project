const mongoose = require('mongoose');
const bcrypt = require('bcrypt');

const userSchema = new mongoose.Schema({
  name: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  password_hash: { type: String, required: true },
  role: { type: String, enum: ['superadmin', 'admin', 'L1', 'L2', 'L3', 'L4'], required: true },
}, { timestamps: true });

// Helper methods for hashing and comparing passwords
userSchema.statics.hashPass = async function(password) {
  return await bcrypt.hash(password, 15);
};

userSchema.statics.verifyPass = async function(password, passwordHash) {
  return await bcrypt.compare(password, passwordHash);
};

const UserModel = mongoose.model('User', userSchema, 'users');

module.exports = UserModel;