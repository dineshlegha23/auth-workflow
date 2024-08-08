const {
  login,
  logout,
  register,
  verifyEmail,
} = require("../controllers/authController");

const express = require("express");
const { authenticateUser } = require("../middleware/authentication");
const router = express.Router();

router.delete("/logout", authenticateUser, logout);
router.post("/login", login);
router.post("/register", register);
router.post("/verify-email", verifyEmail);

module.exports = router;
