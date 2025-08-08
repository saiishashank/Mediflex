const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");

const doctorSchema = new mongoose.Schema({
  email: {
    type: String,
    required: [true, "Please tell us your email"]

  },
  name: {
    type: String,
    required: [true, "Please tell us your Name"],
  },
  hospitalname: {
    type: String,
    required: [true, "Please tell us your Hospital Name"],
  },
  contactnumber: {
    type: Number,
    required: [true, "Please tell us your Contact Number"],
  },
  password: {
    type: String,
    required: [true, "Please provide a password"],
    
  },
   appointments: [
    {
      date: {
        type: Date,
        required: true,
      },
      patient: {
        type: mongoose.Schema.ObjectId,
        ref: "User", // This creates a reference to the User model
        required: true,
      },
    },
  ],
});

doctorSchema.pre("save", async function (next) {
  if (!this.isModified("password")) return next();
  this.password = await bcrypt.hash(this.password, 12);
  next();
});

const Doctor = mongoose.model("Doctor", doctorSchema);
module.exports = Doctor;
