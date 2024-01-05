const User = require("../model/userModel");
const catchAsync = require("../utils/catchAsync");
const AppError = require("../utils/appError");
const { signToken, verifyToken } = require("../utils/manageAuthToken");
const sendEmail = require("../utils/email");

exports.signup = catchAsync(async (req, res, next) => {
  const { name, email, password } = req.body;
  const newUser = await User.create({
    name,
    email,
    password
  });

  console.log(newUser)

  const authToken = signToken({ id: newUser._id });

  res.status(201).json({
    status: "success",
    authToken,
    data: {
      user: newUser,
    },
  });
});

exports.login = catchAsync(async (req, res, next) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return next(new AppError("Please provide email and password!", 400));
  }

  const user = await User.findOne({ email }).select("+password");

  if (!user || !(await user.verifyPassword(password, user.password))) {
    return next(new AppError("Invalid email or password!", 400));
  }

  const authToken = signToken({ id: user._id });

  res.status(200).json({
    status: "success",
    authToken,
  });
});

exports.protect = catchAsync(async (req, res, next) => {
  //Get JWT
  const authToken = req.headers.authorization;

  if (!authToken) {
    return next(
      new AppError("You are not logged in! Please log in to get access.", 401)
    );
  }

  //Verify JWT
  const isJwtValid = await verifyToken(authToken);

  if (!isJwtValid) {
    return next(
      new AppError("You are not authorized to access this resource!", 401)
    );
  }

  //Check if user still exist
  const user = await User.findById(isJwtValid.id);

  if (!user) {
    return next(new AppError("This user doesn't exist anymore", 400));
  }

  //Check if password was changed after signing JWT
  if (user.changedPasswordAfterToken(isJwtValid.iat)) {
    return next(
      new AppError(
        "Password has been changed recently! Please log in again.",
        401
      )
    );
  }

  req.user = user;

  next();
});



exports.forgotPassword = catchAsync(async (req, res, next) => {
  const { email } = req.body;
  const user = await User.findOne({ email });

  if (!user) {
    return next(
      new AppError(`There's no user with this email id: ${email}`, 404)
    );
  }

  const passwordResetToken = user.generateResetPasswordToken();
  await user.save({ validateBeforeSave: false });

  const resetUrl = `${req.protocol}://${req.get(
    "host"
  )}/api/v1/users/resetPassword/${passwordResetToken}`;

  const message = `Forgot password? Don't worry reset from here - ${resetUrl}`;

  try {
    await sendEmail({
      email: user.email,
      subject: "Reset Password",
      message,
    });

    res.status(200).json({
      status: "success",
      message: "Password reset email sent!",
    });
  } catch (err) {
    user.passwordResetToken = undefined;
    user.passwordResetTokenExpires = undefined;
    await user.save({ validateBeforeSave: false });

    next(
      new AppError(
        "Something went wrong with sending password reset email. Please try again later!",
        500
      )
    );
  }
});

exports.resetPassword = catchAsync(async (req, res, next) => {});
