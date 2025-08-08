const User = require("../models/userModel");
const jwt = require("jsonwebtoken");
const AppError = require("../utils/appError");
const { promisify } = require("util");
const bcrypt = require("bcryptjs");
const { catchAsync } = require("../utils/catchAsync");
const Doctor = require("../models/doctorModel");

const signToken = (id, type) => {
  return jwt.sign({ id, type }, process.env.JWT_S, {
    expiresIn: process.env.JWT_E,
  });
};
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

exports.signup = async (req, res, next) => {
  try {
    const newUser = await User.create({
      name: req.body.name,
      email: req.body.email,
      password: req.body.password,
    });
    createSendToken(newUser, 201, res, 'patient');
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

  const user = await User.findOne({ email }).select("+password");

  if (!user || !(await bcrypt.compare(password, user.password))) {
    return next(new AppError("Incorrect email or password", 401));
  }

  createSendToken(user, 200, res, 'patient');
});

exports.logout = (req, res) => {
  res.cookie('jwt', 'loggedout', {
    expires: new Date(Date.now() + 10 * 1000),
    httpOnly: true,
  });
  res.status(200).json({ status: 'success' });
};


// --- MIDDLEWARE ---

exports.protect = catchAsync(async (req, res, next) => {
  let token;
  if (req.headers.authorization && req.headers.authorization.startsWith("Bearer")) {
    token = req.headers.authorization.split(" ")[1];
  } else if (req.cookies.jwt) {
    token = req.cookies.jwt;
  }

  if (!token) {
    return next(new AppError("You are not logged in! Please log in to get access.", 401));
  }

  const decoded = await promisify(jwt.verify)(token, process.env.JWT_S);

  let currentUser;
  if (decoded.type === 'doctor') {
    currentUser = await Doctor.findById(decoded.id);
  } else if (decoded.type === 'patient') {
    currentUser = await User.findById(decoded.id);
  } else {
    return next(new AppError("Invalid token type.", 401));
  }
  
  if (!currentUser) {
    return next(new AppError("The user belonging to this token no longer exists.", 401));
  }

  req.user = currentUser;
  next();
});


// --- USER DATA ---

exports.getMe = (req, res, next) => {
  req.params.id = req.user.id;
  next();
};

exports.getCurrentUser = catchAsync(async (req, res, next) => {
  let user = req.user; // User or Doctor document from the 'protect' middleware.

  // If the logged-in user is a doctor (we can check for a unique doctor field),
  // we must re-fetch their data to populate the appointments.
  if (user.hospitalname !== undefined) { 
    user = await Doctor.findById(user.id).populate({
      path: 'appointments.patient', // The path to populate
      select: 'name email'        // The patient fields you want
    });
  }

  // If the user wasn't found after populating (edge case)
  if (!user) {
    return next(new AppError('The user for this token could not be found.', 404));
  }
  
  // Send the final, populated user data
  res.status(200).json({
    status: 'success',
    data: {
      data: user
    }
  });
});
exports.getUser = catchAsync(async (req, res, next) => {
  const user = await User.findById(req.params.id);
  if (!user) {
    return next(new AppError('No user found with that ID', 404));
  }
  res.status(200).json({
    status: 'success',
    data: { data: user }
  });
});

exports.isLoggedIn = async (req, res, next) => {
  if (req.cookies.jwt) {
    try {
      const decoded = await promisify(jwt.verify)(
        req.cookies.jwt,
        process.env.JWT_S
      );
      const currentUser = await User.findById(decoded.id);
      if (!currentUser) {
        return next();
      }
      if (currentUser.changedPasswordAfter(decoded.iat)) {
        return next();
      }
      res.locals.user = currentUser;
    } catch (error) {
      return next();
    }
  }
  return next();
};

exports.updateSugar = catchAsync(async (req, res, next) => {
  const sugarValue = req.body.sugar;
  const user = await User.findByIdAndUpdate(
    req.user._id,
    { $push: { sugar: sugarValue } },
    { new: true, runValidators: true }
  );
  if (!user) {
    return res.status(404).json({
      status: "fail",
      message: "User not found",
    });
  }
  res.status(200).json({
    status: "success",
    data: {
      user,
    },
  });
});
exports.updateBP = catchAsync(async (req, res, next) => {
  const { bp } = req.body;

  if (!bp) {
    return res.status(400).json({
      status: "fail",
      message: "BP value is required",
    });
  }

  const user = await User.findByIdAndUpdate(
    req.user._id,
    { $push: { bp: bp } },
    { new: true, runValidators: true }
  );

  if (!user) {
    return res.status(404).json({
      status: "fail",
      message: "User not found",
    });
  }

  res.status(200).json({
    status: "success",
    data: {
      user,
    },
  });
});

// Upload Image
exports.uploadImage = catchAsync(async (req, res, next) => {
  const { document } = req.body; // Get the base64 string

  if (!document) {
    return next(new AppError('Document is required.', 400));
  }

  const user = await User.findById(req.user._id);
  if (!user) {
    return next(new AppError('User not found', 404));
  }

  user.images.push(document); // Add base64 image to the user's images array
  await user.save();

  res.status(200).json({
    status: 'success',
    message: 'File uploaded successfully.',
  });
});

// Get User Images
exports.getUserImages = catchAsync(async (req, res, next) => {
  const user = await User.findById(req.user._id);
  if (!user) {
    return next(new AppError('User not found', 404));
  }

  res.status(200).json({
    status: 'success',
    images: user.images, // Return the array of base64 images
  });
});

