const jwt = require("jsonwebtoken");
const crypto = require("crypto");

//generating jwt token
const generateToken = (id) => {
  return jwt.sign({ id }, process.env.JWT_SECRET, { expiresIn: "1d" });
};

//hash token
// data has to be string method incase for prob
const hashToken = (token) => {
  return crypto.createHash("sha256").update(token.toString()).digest("hex");
};

module.exports = {
  generateToken,
  hashToken,
};
