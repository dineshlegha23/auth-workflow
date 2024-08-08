const { createJWT, isTokenValid, attachCookiesToResponse } = require("./jwt");
const createTokenUser = require("./createTokenUser");
const checkPermissions = require("./checkPermissions");
const sendVerificationEmail = require("./sendVerificationEmail");
const sendResetPassowrdEmail = require("./sendResetPasswordEmail");

module.exports = {
  createJWT,
  isTokenValid,
  attachCookiesToResponse,
  createTokenUser,
  checkPermissions,
  sendVerificationEmail,
  sendResetPassowrdEmail,
};
