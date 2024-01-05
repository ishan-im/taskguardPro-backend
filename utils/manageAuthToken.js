const { promisify } = require("util");
const jwt = require("jsonwebtoken");

exports.signToken = (payload) => {
  const token = jwt.sign(payload, process.env.JWT_SECRET, {
    expiresIn: process.env.JWT_EXPIRES_IN,
  });

  return token;
};

exports.verifyToken = async (authToken) => {
  return await promisify(jwt.verify)(authToken, process.env.JWT_SECRET);
};
