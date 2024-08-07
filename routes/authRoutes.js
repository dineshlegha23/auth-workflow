const {
  login,
  logout,
  register,
  verifyEmail,
} = require("../controllers/authController");

const express = require("express");
const router = express.Router();

router.get("/logout", logout);
router.post("/login", login);
router.post("/register", register);
router.post("/verify-email", verifyEmail);

module.exports = router;
