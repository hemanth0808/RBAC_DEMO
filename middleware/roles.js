// roles.js
module.exports = function (roles) {
  return (req, res, next) => {
    console.log("User role:", req.user?.role);
    if (!roles.includes(req.user.role)) {
      return res.status(403).json({ message: "Access forbidden" });
    }
    next();
  };
};
