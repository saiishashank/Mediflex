const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");
const userSchema = new mongoose.Schema({
  email: {
    type: String,
    required: [true, "Please tell us your email"],
  },
  name: {
    type: String,
    required: [true, "Please tell us your Name"],
  },
  password: {
    type: String,
    required: [true, "Please provide a password"],
  },
  bp: [{ type: String }],
  sugar: [{ type: String }],
  images: {
    type: [String],  // Array to store base64 image strings
    default: []
  },

});
userSchema.pre("save", async function (next) {
  if (!this.isModified("password")) return next();
  this.password = await bcrypt.hash(this.password, 12);
  this.passwordConfirm = undefined;
  next();
});
const User = mongoose.model("User", userSchema);
module.exports = User;
