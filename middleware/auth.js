// auth.js
const jwt = require("jsonwebtoken");
const dotenv = require("dotenv");
dotenv.config();

module.exports = function (req, res, next) {
  const token = req.header("Authorization")?.split(" ")[1];
  if (!token) return res.status(401).json({ message: "Access denied" });

  try {
    const verified = jwt.verify(token, process.env.JWT_SECRET);
    req.user = verified;
    console.log("Verified user:", req.user);
    next();
  } catch (err) {
    res.status(400).json({ message: "Invalid token" });
  }
};
