const jwt = require("jsonwebtoken");
const factory = require("./handleFactory");
const Doctor = require("../models/doctorModel");
const { promisify } = require("util");
const bcrypt = require("bcryptjs");
const { AppError } = require("../utils/appError");
const { catchAsync } = require("../utils/catchAsync");
const { findByIdAndUpdate } = require("../models/doctorModel");
const User = require("../models/userModel");
const signToken = (id) => {
  return jwt.sign({ id }, process.env.JWT_S, {
    expiresIn: process.env.JWT_E,
  });
};

const createSendToken = (user, statusCode, res) => {
  const token = signToken(user._id);
  const cookieOptions = {
    expires: new Date(
      Date.now() + process.env.JWT_COOKIE_EXPIRES_IN * 24 * 60 * 60 * 1000
    ),
    httpOnly: true,
  };

  

  res.cookie("jwt", token, cookieOptions);

  user.password = undefined; // Remove password from output

  res.status(statusCode).json({
    status: "success",
    token,
    data: {
      user,
    },
  });
};

exports.signup = async (req, res) => {
  try {
    const newUser = await Doctor.create(req.body);
    createSendToken(newUser, 201, res); // Use createSendToken to send the response
  } catch (err) {
    console.log(err);
    res.status(400).json({
      status: "fail",
      message: err.message,
    });
  }
};

exports.login = catchAsync(async (req, res, next) => {
  const { email, password } = req.body;
  console.log(req.body);

  const user = await Doctor.findOne({ email }).select("+password");
  if (!user || !(await bcrypt.compare(password, user.password))) {
    return next(new AppError("Incorrect email or password", 401));
  }
  createSendToken(user, 200, res);
});
exports.getAllDoctors = async (req, res) => {
  try {
    const allUser = await Doctor.find({});
    res.status(200).send({
      status: "success",
      allUser,
    });
  } catch (err) {
    console.log(err);
    res.status(400).json({
      status: "fail",
      message: err.message,
    });
  }
};
exports.getMe = (req, res, next) => {
  req.params.id = req.user.id;
  next();
};
exports.getUser = factory.getOne(Doctor);

exports.protect = catchAsync(async (req, res, next) => {
  let token;
  if (
    req.headers.authorization &&
    req.headers.authorization.startsWith("Bearer")
  ) {
    token = req.headers.authorization.split(" ")[1];
  } else if (req.cookies.jwt) {
    token = req.cookies.jwt;
  }
  console.log(token);
  if (!token) {
    return next(new AppError("you are not logged in! please login", 401));
  }
  const decoded = await promisify(jwt.verify)(token, process.env.JWT_S);
  let query = Doctor.findById(decoded.id);
  const currentUser = await query;
  if (!currentUser) {
    return next(
      new Error("The user belonging to this token no longer exist", 401)
    );
  }
  req.user = currentUser;
  res.locals.user = currentUser;
  next();
});
exports.update = catchAsync(async (req, res, next) => {
  const id = req.params.id;
  const currentUser = req.body.user;
  const date = req.body.date;
  console.log(req.user);
  console.log(req.params.id);
  const patient = await User.findById(req.user);
  console.log(patient);
  //   if (!user12) {
  //     return res.status(404).json({
  //       status: "fail",
  //       message: "User not found.",
  //     });
  //   }
  const doc = await Doctor.findByIdAndUpdate(
    req.params.id,
    {
      $push: {
        appointments: { patient: patient, date: date },
      },
    },
    {
      new: true,
      runValidators: true,
    }
  );
  //   if (!doc) {
  //     return res.status(404).json({
  //       status: "fail",
  //       message: "Doctor not found.",
  //     });
  //   }
  res.status(200).json({
    status: "success",
    data: {
      doctor: doc,
    },
  });
});