const { config } = require("../config");
const asyncHandler = require("../utils/asyncHandler");
const { BadRequestError } = require("../utils/error");
const authService = require("../services/auth.service");


exports.sendOTP = asyncHandler( async (req, res) => {

    const {firstName, lastName, email, password, confirmPassword} = req.body;

    if(!firstName || !lastName || !email || !password || !confirmPassword){
        throw new BadRequestError("All fields are required");
    }

    if(password !== confirmPassword){
        throw new BadRequestError("Password and confirmed password do not match");
    }

    const {otpSessionId, otp} = await authService.sendOTP(firstName, lastName, email, password);

    res.cookie("otp_session", otpSessionId,{
        httpOnly: true,
        secure: true,
        sameSite: true,
        maxAge: config.OTP_TTL * 1000
    }).status(200).json({
        message: "OTP generated successfully",
        otp: otp,
        otpSessionId: otpSessionId
    });
}) 

exports.verifyOTP = asyncHandler( async (req, res) => {
    const {otp} = req.body;
    const otpSessionId = req.cookies.otp_session;

    if(!otp || !otpSessionId){
        throw new BadRequestError("OTP and OTP session are required");
    }

    const user = await authService.verifyOTP(otpSessionId, otp);

    if(!user){
        throw new BadRequestError("Invalid OTP");
    }

    return res.status(201).json({
        message: "User registered successfully",
        success: true,
        data: user
    });

});

// module.exports = {
//     sendOTP
// }