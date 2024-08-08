const {
  login,
  logout,
  register,
  verifyEmail,
  resetPassword,
  forgotPassword,
} = require("../controllers/authController");

const express = require("express");
const { authenticateUser } = require("../middleware/authentication");
const router = express.Router();

router.delete("/logout", authenticateUser, logout);
router.post("/login", login);
router.post("/register", register);
router.post("/verify-email", verifyEmail);
router.post("/reset-password", resetPassword);
router.post("/forgot-password", forgotPassword);

module.exports = router;
