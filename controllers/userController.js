// used to handle asynch errors try catch blocks
const asyncHandler = require("express-async-handler");
const jwt = require("jsonwebtoken");

const User = require("../models/userModel");
const bcrypt = require("bcryptjs");
const { generateToken, hashToken } = require("../utils");
// used for user agent
var parser = require("ua-parser-js");
const sendEmail = require("../utils/sendEmail");

const Token = require("../models/tokenModel");
//one way hashing
const crypto = require("crypto");
// hashing crypting both ways decrypt
const Cryptr = require("cryptr");
const { OAuth2Client } = require("google-auth-library");
const cryptr = new Cryptr(process.env.CRYPTR_KEY);

const client = new OAuth2Client(process.env.GOOGLE_CLIENT_ID);

//

// Register User
const registerUser = asyncHandler(async (req, res) => {
  const { name, email, password } = req.body;

  // Validation
  if (!name || !email || !password) {
    res.status(400);
    throw new Error("Please fill in all the required fields.");
  }

  if (password.length < 6) {
    res.status(400);
    throw new Error("Password must be up to 6 characters.");
  }

  // Check if user exists
  const userExists = await User.findOne({ email });

  if (userExists) {
    res.status(400);
    throw new Error("Email already in use.");
  }
  // get user  agent
  //details about user device
  // ua.ua object ua saved as array
  const ua = parser(req.headers["user-agent"]);
  const userAgent = [ua.ua];

  //   Create new user
  const user = await User.create({
    name,
    email,
    password,
    userAgent,
  });

  // Generate Token
  //mongodb default user i.d
  const token = generateToken(user._id);

  //http cookie send

  res.cookie("token", token, {
    path: "/",
    httpOnly: true,
    expires: new Date(Date.now() + 1000 * 86400), // 1 day expires
    sameSite: "none",
    secure: true,
  });

  //if user was actually created (create new user)
  if (user) {
    const { _id, name, email, phone, bio, photo, role, isVerified } = user; //user all properties destruct

    res
      .status(201)
      .json({ _id, name, email, phone, bio, photo, role, isVerified, token });
  } else {
    res.status(400);
    throw new Error("invalid user data");
  }
});
//login user
const loginUser = asyncHandler(async (req, res) => {
  const { email, password } = req.body;

  // validation
  if (!email || !password) {
    res.status(400);
    throw new Error("Please add email and password");
  }

  const user = await User.findOne({ email });

  if (!user) {
    res.status(400);
    throw new Error("user not found, please sign up");
  }

  // check this login password with db user.password stored and  compare
  const passwordIsCorrect = await bcrypt.compare(password, user.password);
  if (!passwordIsCorrect) {
    res.status(400);
    throw new Error("invalid email or password");
  }

  // trigger 2fa for unknown user agent

  const ua = parser(req.headers["user-agent"]);
  //device the client logging in
  const thisuserAgent = ua.ua;
  console.log(thisuserAgent);
  const allowedAgent = user.userAgent.includes(thisuserAgent);

  if (!allowedAgent) {
    //generate 6 digit code
    const loginCode = Math.floor(100000 + Math.random() * 900000);
    console.log(loginCode);

    //encrypt login code before saving to db
    //makesure to string it incase
    const encryptedLoginCode = cryptr.encrypt(loginCode.toString());
    console.log(encryptedLoginCode);

    //delete token if it exist in db
    let usertoken = await Token.findOne({ userId: user._id });
    if (usertoken) {
      await usertoken.deleteOne();
    }

    // hash token and save

    // saving new token to db
    await new Token({
      userId: user._id,
      lToken: encryptedLoginCode,
      createdAt: Date.now(),
      expiresAt: Date.now() + 60 * (60 * 1000), // 60 mins
    }).save();

    res.status(400);
    throw new Error("New browser or device detected");
  }

  //generate token
  const token = generateToken(user._id);

  // send http cookie to front end
  //sends token to be stored

  if (user && passwordIsCorrect) {
    res.cookie("token", token, {
      path: "/",
      httpOnly: true,
      expires: new Date(Date.now() + 1000 * 86400), // 1 day expires
      sameSite: "none",
      secure: true,
    });

    const { _id, name, email, phone, bio, photo, role, isVerified } = user; //user all properties destruct
    // send to front end
    res
      .status(200)
      .json({ _id, name, email, phone, bio, photo, role, isVerified, token });
  } else {
    res.status(500);
    throw new Error("invalid email or password");
  }
});
//logout user
const logoutUser = asyncHandler(async (req, res) => {
  // sending to client keep the name of token but delete token object to "" string
  res.cookie("token", "", {
    path: "/",
    httpOnly: true,
    expires: new Date(0), // change the to 0
    sameSite: "none",
    secure: true,
  });
  return res.status(200).json({ message: "logout success" });
});

const getUser = asyncHandler(async (req, res) => {
  // accesing by authmiddleware protect req.user
  const user = await User.findById(req.user._id);
  if (user) {
    const { _id, name, email, phone, bio, photo, role, isVerified } = user; //user all properties destruct
    // send to front end
    res
      .status(200)
      .json({ _id, name, email, phone, bio, photo, role, isVerified });
  } else {
    res.status(500);
    throw new Error("invalid email or password");
  }
});

//update user
//data coming from front end
const updateUser = asyncHandler(async (req, res) => {
  //using auth middleware protect to get req.user
  const user = await User.findById(req.user._id);
  if (user) {
    const { _id, name, email, phone, bio, photo, role, isVerified } = user; //user all properties destruct

    // using or keep default if not updated
    user.email = email;
    user.name = req.body.name || name;
    user.phone = req.body.phone || phone;
    user.bio = req.body.bio || bio;
    user.photo = req.body.photo || photo;

    // save the updated data
    const updatedUser = await user.save();
    // sending to front end
    res.status(200).json({
      _id: updatedUser._id,
      name: updatedUser.name,
      email: updatedUser.email,
      phone: updatedUser.phone,
      bio: updatedUser.bio,
      photo: updatedUser.photo,
      role: updatedUser.role,
      isVerified: updatedUser.isVerified,
    });
  } else {
    res.status(500);
    throw new Error("user not found");
  }
});

//deleteuser
const deleteUser = asyncHandler(async (req, res) => {
  const user = User.findById(req.params.id);

  if (!user) {
    res.status(404);
    throw new Error("user not found");
  }
  await user.remove();
  res.status(200).json({
    message: "user deleted succesfully",
  });
});

// get users
const getUsers = asyncHandler(async (req, res) => {
  // sort the latest user by -createdat
  //only author and admin get all users middleware

  const users = await User.find().sort("-createdAt").select("-password");
  if (!users) {
    res.status(500);
    throw new Error("something went rong");
  }
  res.status(200).json(users);
});

//get login status
const loginStatus = asyncHandler(async (req, res) => {
  //get token from browser, name of the cookie .token
  const token = req.cookies.token;
  if (!token) {
    return res.json(false);
  }

  //verify token
  const verified = jwt.verify(token, process.env.JWT_SECRET);
  if (verified) {
    return res.json(true);
  }
  return res.json(false);
});

const upgradeUser = asyncHandler(async (req, res) => {
  //coming from front end req.body
  const { role, id } = req.body;
  const user = await User.findById(id);
  if (!user) {
    res.status(404);
    throw new Error("user not found");
  }

  user.role = role;
  await user.save();

  res.status(200).json({ message: `user role update to ${role}` });
});

// send autamted email
const sendAutomatedEmail = asyncHandler(async (req, res) => {
  //sent from front end
  const { subject, send_to, reply_to, template, url } = req.body;

  if (!subject || !send_to || !reply_to || !template) {
    res.status(500);
    throw new Error("miising email parameter");
  }
  //get user
  const user = await User.findOne({ email: send_to });
  if (!user) {
    res.status(404);
    throw new Error("user not found");
  }

  const sent_from = process.env.EMAIL_USER;
  const name = user.name;
  console.log(name);
  const link = `${process.env.FRONTEND_URL}${url}`;

  try {
    await sendEmail(
      subject,
      send_to,
      sent_from,
      reply_to,
      template,
      name,
      link
    );

    res.status(200).json({ message: "email sent" });
  } catch (error) {
    res.status(500);
    throw new Error("email not sent please try again");
  }
});

//send verification email
const sendVerificationEmail = asyncHandler(async (req, res) => {
  const user = await User.findById(req.user._id);

  if (!user) {
    res.status(400);
    throw new Error("user not found");
  }

  if (user.verified) {
    res.status(400);
    throw new Error("user already verified");
  }

  //delete token if it exist in db
  let token = await Token.findOne({ userId: user._id });
  if (token) {
    await token.deleteOne();
  }

  // create verification and save

  const verificationToken = crypto.randomBytes(32).toString("hex") + user._id;
  console.log(verificationToken);

  // hash token and save
  //hash token before saving to db
  const hashedToken = hashToken(verificationToken);
  // saving new token to db
  await new Token({
    userId: user._id,
    vToken: hashedToken,
    createdAt: Date.now(),
    expiresAt: Date.now() + 60 * (60 * 1000), // 60 mins
  }).save();

  // construct verification url
  const verificationUrl = `${process.env.FRONTEND_URL}/verify/${verificationToken}`;

  // send email
  const subject = "verify your account m";
  const send_to = user.email;
  const sent_from = process.env.EMAIL_USER;
  const reply_to = "noreply@googlemail.com";
  const template = "verifyEmail";
  const name = user.name;
  const link = verificationUrl;

  try {
    await sendEmail(
      subject,
      send_to,
      sent_from,
      reply_to,
      template,
      name,
      link
    );

    res.status(200).json({ message: "verification email sent" });
  } catch (error) {
    res.status(500);
    throw new Error("email not sent please try again");
  }
});

//verify user token coming from front end
const verifyUser = asyncHandler(async (req, res) => {
  const { verificationToken } = req.params;

  const hashedToken = hashToken(verificationToken);
  //check database for hashed
  // check date greater than
  const userToken = await Token.findOne({
    vToken: hashedToken,
    expiresAt: { $gt: Date.now() },
  });

  if (!userToken) {
    res.status(404);
    throw new Error("invalid or expired ");
  }

  // find user using userid on token
  const user = await User.findOne({ _id: userToken.userId });

  if (user.isVerified) {
    res.status(400);
    throw new Error("user is already verified ");
  }

  //now verify user and save it to db
  user.isVerified = true;
  await user.save();

  res.status(200).json({ message: "account verification succesful" });
});

//forgot password
const forgotPassword = asyncHandler(async (req, res) => {
  // email coming from front end
  const { email } = req.body;

  const user = await User.findOne({ email });

  if (!user) {
    res.status(404);
    throw new Error("no user with this email");
  }

  //delete token if it exist in db
  let token = await Token.findOne({ userId: user._id });
  if (token) {
    await token.deleteOne();
  }

  // create resettoken and save

  const resetToken = crypto.randomBytes(32).toString("hex") + user._id;
  console.log(resetToken);

  // hash token and save
  //hash token before saving to db
  const hashedToken = hashToken(resetToken);
  // saving new token to db
  await new Token({
    userId: user._id,
    rToken: hashedToken,
    createdAt: Date.now(),
    expiresAt: Date.now() + 60 * (60 * 1000), // 60 mins
  }).save();

  // construct reset url
  const resetUrl = `${process.env.FRONTEND_URL}/resetPassword/${resetToken}`;

  // send email
  const subject = "password reset request";
  const send_to = user.email;
  const sent_from = process.env.EMAIL_USER;
  const reply_to = "noreply@googlemail.com";
  const template = "forgotPassword";
  const name = user.name;
  const link = resetUrl;

  try {
    await sendEmail(
      subject,
      send_to,
      sent_from,
      reply_to,
      template,
      name,
      link
    );

    res.status(200).json({ message: "password reset email sent" });
  } catch (error) {
    res.status(500);
    throw new Error("email not sent please try again");
  }
});

//reset password
//2 thing token from front param end and new password from front end
const resetPassword = asyncHandler(async (req, res) => {
  const { resetToken } = req.params;
  const { password } = req.body;

  const hashedToken = hashToken(resetToken);
  //check database for hashed
  // check date greater than
  const userToken = await Token.findOne({
    rToken: hashedToken,
    expiresAt: { $gt: Date.now() },
  });

  if (!userToken) {
    res.status(404);
    throw new Error("invalid or expired ");
  }

  // find user using userid on token
  const user = await User.findOne({ _id: userToken.userId });

  //now reset password and save it to db
  user.password = password;
  await user.save();

  res.status(200).json({ message: "password Reset Successful" });
});

//change password
const changePassword = asyncHandler(async (req, res) => {
  // get old password and new password from frontend
  const { oldPassword, password } = req.body;
  const user = await User.findById(req.user._id);

  if (!user) {
    res.status(404);
    throw new Error("user not found");
  }
  ////////// problem coming from here frontend was oldPassword but here was oldpassword
  if (!oldPassword || !password) {
    res.status(404);
    throw new Error("please enter new and old password");
  }
  // check if old passsword is correct
  const passwordIsCorrect = bcrypt.compare(oldPassword, user.password);

  // save new password to db
  if (user && passwordIsCorrect) {
    user.password = password;
    await user.save();

    res
      .status(200)
      .json({ message: "password change succesfull please login" });
  } else {
    res.status(400);
    throw new Error("old password incorrect");
  }
});

//send login code
const sendLoginCode = asyncHandler(async (req, res) => {
  //destructuring frontend params email
  const { email } = req.params;
  const user = await User.findOne({ email });

  if (!user) {
    res.status(404);
    throw new Error("user not found");
  }

  //find login code in db
  let userToken = await Token.findOne({
    userId: user._id,
    expiresAt: { $gt: Date.now() },
  });
  if (!userToken) {
    res.status(500);
    throw new Error("expired or invalid token");
  }
  const loginCode = userToken.lToken;
  const decryptedLoginCode = cryptr.decrypt(loginCode);

  //send email
  const subject = "login acces code";
  const send_to = email; // destructured param email
  const sent_from = process.env.EMAIL_USER;
  const reply_to = "noreply@googlemail.com";
  const template = "loginCode";
  const name = user.name;
  const link = decryptedLoginCode;

  try {
    await sendEmail(
      subject,
      send_to,
      sent_from,
      reply_to,
      template,
      name,
      link
    );

    res.status(200).json({ message: "access code sent to email" });
  } catch (error) {
    res.status(500);
    throw new Error("email not sent please try again");
  }
});

// Login With Code
const loginWithCode = asyncHandler(async (req, res) => {
  const { email } = req.params;
  const { loginCode } = req.body;

  const user = await User.findOne({ email });

  if (!user) {
    res.status(404);
    throw new Error("User not found");
  }

  // Find user Login Token
  const userToken = await Token.findOne({
    userId: user.id,
    expiresAt: { $gt: Date.now() },
  });

  if (!userToken) {
    res.status(404);
    throw new Error("Invalid or Expired Token, please login again");
  }

  const decryptedLoginCode = cryptr.decrypt(userToken.lToken);

  if (loginCode !== decryptedLoginCode) {
    res.status(400);
    throw new Error("Incorrect login code, please try again");
  } else {
    // Register userAgent
    const ua = parser(req.headers["user-agent"]);
    const thisUserAgent = ua.ua;
    user.userAgent.push(thisUserAgent);
    await user.save();

    // Generate Token
    const token = generateToken(user._id);

    // Send HTTP-only cookie
    res.cookie("token", token, {
      path: "/",
      httpOnly: true,
      expires: new Date(Date.now() + 1000 * 86400), // 1 day
      sameSite: "none",
      secure: true,
    });

    const { _id, name, email, phone, bio, photo, role, isVerified } = user;

    res.status(200).json({
      _id,
      name,
      email,
      phone,
      bio,
      photo,
      role,
      isVerified,
      token,
    });
  }
});

const loginWithGoogle = asyncHandler(async (req, res) => {
  const { userToken } = req.body;
  //   console.log(userToken);

  const ticket = await client.verifyIdToken({
    idToken: userToken,
    audience: process.env.GOOGLE_CLIENT_ID,
  });

  const payload = ticket.getPayload();
  const { name, email, picture, sub } = payload;
  const password = Date.now() + sub;

  // Get UserAgent
  const ua = parser(req.headers["user-agent"]);
  const userAgent = [ua.ua];

  // Check if user exists
  const user = await User.findOne({ email });

  if (!user) {
    //   Create new user
    const newUser = await User.create({
      name,
      email,
      password,
      photo: picture,
      isVerified: true,
      userAgent,
    });

    if (newUser) {
      // Generate Token
      const token = generateToken(newUser._id);

      // Send HTTP-only cookie
      res.cookie("token", token, {
        path: "/",
        httpOnly: true,
        expires: new Date(Date.now() + 1000 * 86400), // 1 day
        sameSite: "none",
        secure: true,
      });

      const { _id, name, email, phone, bio, photo, role, isVerified } = newUser;

      res.status(201).json({
        _id,
        name,
        email,
        phone,
        bio,
        photo,
        role,
        isVerified,
        token,
      });
    }
  }

  // User exists, login
  if (user) {
    const token = generateToken(user._id);

    // Send HTTP-only cookie
    res.cookie("token", token, {
      path: "/",
      httpOnly: true,
      expires: new Date(Date.now() + 1000 * 86400), // 1 day
      sameSite: "none",
      secure: true,
    });

    const { _id, name, email, phone, bio, photo, role, isVerified } = user;

    res.status(201).json({
      _id,
      name,
      email,
      phone,
      bio,
      photo,
      role,
      isVerified,
      token,
    });
  }
});

module.exports = {
  registerUser,
  loginUser,
  logoutUser,
  getUser,
  updateUser,
  deleteUser,
  getUsers,
  loginStatus,
  upgradeUser,
  sendAutomatedEmail,
  sendVerificationEmail,
  verifyUser,
  forgotPassword,
  resetPassword,
  changePassword,
  sendLoginCode,
  loginWithCode,
  loginWithGoogle,
};
