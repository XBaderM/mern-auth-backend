const asyncHandler = require("express-async-handler");
const User = require("../models/userModel");
const jwt = require("jsonwebtoken");

const protect = asyncHandler(async (req, res, next) => {
  try {
    //saved cookies on client req
    const token = req.cookies.token;
    if (!token) {
      res.status(401);
      throw new Error("not authorised please lohg in");
    }
    //verify token
    const verified = jwt.verify(token, process.env.JWT_SECRET);
    //get user id from token
    //use select to not send passsword by using minus-
    const user = await User.findById(verified.id).select("-password");
    if (!user) {
      res.status(404);
      throw new Error("user not found");
    }
    //block access with middleware
    if (user.role === "suspended") {
      res.status(400);
      throw new Error("user suspended, please contact support");
    }

    req.user = user;
    //after middleware will fire next
    next();
  } catch (error) {
    res.status(401);
    throw new Error("not authorised please lohg in");
  }
});

const adminOnly = asyncHandler(async (req, res, next) => {
  if (req.user && req.user.role === "admin") {
    next();
  } else {
    res.status(401);
    throw new Error("not authorised as admin");
  }
});

const authorOnly = asyncHandler(async (req, res, next) => {
  if (req.user.role === "author" || req.user.role === "admin") {
    next();
  } else {
    res.status(401);
    throw new Error("not authorised as author");
  }
});

const verifiedOnly = asyncHandler(async (req, res, next) => {
  if (req.user && req.user.isVerified === "admin") {
    next();
  } else {
    res.status(401);
    throw new Error("not authorised as author account not verified");
  }
});

module.exports = {
  protect,
  verifiedOnly,
  adminOnly,
  authorOnly,
};
