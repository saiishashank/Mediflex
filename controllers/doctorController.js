const jwt = require("jsonwebtoken");
const Doctor = require("../models/doctorModel");
const { promisify } = require("util");
const bcrypt = require("bcryptjs");
const { AppError } = require("../utils/appError");
const { catchAsync } = require("../utils/catchAsync");
const User = require("../models/userModel");

const signToken = (id, type) => {
  return jwt.sign({ id, type }, process.env.JWT_S, {
    expiresIn: process.env.JWT_E,
  });
};

/**
 * Signs the token and sends it in the response.
 */
const createSendToken = (user, statusCode, res, type) => {
  const token = signToken(user._id, type);

  const cookieOptions = {
    expires: new Date(
      Date.now() + process.env.JWT_COOKIE_EXPIRES_IN * 24 * 60 * 60 * 1000
    ),
    httpOnly: true,
  };

  if (process.env.NODE_ENV === 'production') {
    cookieOptions.secure = true;
  }
  
  res.cookie("jwt", token, cookieOptions);

  user.password = undefined;
  
  res.status(statusCode).json({ status: "success", token, data: { user } });
};


// --- AUTHENTICATION ---

exports.signup = async (req, res) => {
  try {
    const newDoctor = await Doctor.create({
      name: req.body.name,
      email: req.body.email,
      password: req.body.password,
      hospitalname: req.body.hospitalname,
      contactnumber: req.body.contactnumber,
    });
    createSendToken(newDoctor, 201, res, 'doctor');
  } catch (err) {
    res.status(400).json({
      status: "fail",
      message: err.message,
    });
  }
};

exports.login = catchAsync(async (req, res, next) => {
  const { email, password } = req.body;
  if (!email || !password) {
    return next(new AppError("Please provide email and password", 400));
  }

  const doctor = await Doctor.findOne({ email }).select("+password");

  if (!doctor || !(await bcrypt.compare(password, doctor.password))) {
    return next(new AppError("Incorrect email or password", 401));
  }

  createSendToken(doctor, 200, res, 'doctor');
});


// Get All Doctors
exports.getAllDoctors = async (req, res) => {
  try {
    const allDoctors = await Doctor.find({});
    res.status(200).send({
      status: "success",
      allUser: allDoctors, // Frontend expects `allUser`
    });
  } catch (err) {
    res.status(400).json({
      status: "fail",
      message: err.message,
    });
  }
};


// Update Doctor with Appointment
exports.update = catchAsync(async (req, res, next) => {
  const doctorId = req.params.id;
  const patientId = req.user._id;
  const { date } = req.body;
  const updatedDoctor = await Doctor.findByIdAndUpdate(
    doctorId,
    { $push: { appointments: { patient: patientId, date: date } } },
    { new: true, runValidators: true }
  );
  if (!updatedDoctor) {
    return next(new AppError("Doctor not found.", 404));
  }
  res.status(200).json({
    status: "success",
    data: { doctor: updatedDoctor },
  });
});

// Get Current Doctor's Details (for /me route)
exports.getMe = catchAsync(async (req, res, next) => {
  const doctor = await Doctor.findById(req.user.id).populate({
    path: 'appointments.patient',
    select: 'name email'
  });
  if (!doctor) {
    return next(new AppError('Doctor not found.', 404));
  }
  res.status(200).json({
    status: 'success',
    data: {
      data: doctor 
    }
  });
});