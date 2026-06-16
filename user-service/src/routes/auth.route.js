const express = require("express");
const { sendOTP, verifyOTP, login, rotateRefreshToken } = require("../controllers/auth.controller");
const router = express.Router();


router.post("/send-otp", sendOTP);
router.post("/verify-otp", verifyOTP);
router.post("/login", login);
router.post("/refresh", rotateRefreshToken);

module.exports = router;