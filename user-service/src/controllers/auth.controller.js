const { config } = require("../config");
const asyncHandler = require("../utils/asyncHandler");
const { BadRequestError } = require("../utils/error");
const authService = require("../services/auth.service");
const getDeviceFingerprint = require("../utils/deviceFingerPrint");



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

exports.login = asyncHandler(async(req, res)=>{
    const {email, password} = req.body;

    if(!email || !password){
        throw new BadRequestError("Email and password are required");
    }
    const deviceId = getDeviceFingerprint(req);

    const {accessToken, refreshToken, loggedInUser} = await authService.login(email, password, deviceId);

    res.cookie("accessToken", accessToken,{
        httpOnly: true,
        secure: true,
        sameSite: "strict",
        maxAge: config.ACCESS_TOKEN_EXP_SEC * 1000
    })

    res.cookie("refreshToken", refreshToken,{
        httpOnly: true,
        secure: true,
        sameSite: "strict",
        maxAge: config.REFRESH_TOKEN_EXP_SEC * 1000
    })

    res.status(200).json({
        message: "Login successful",
        success: true,
        loggedInUser
    })
})

exports.rotateRefreshToken = asyncHandler(async(req, res)=>{

    const refreshToken = req.cookies.refreshToken;
    if(!refreshToken) throw new BadRequestError("Refresh token is required");
    const deviceId = getDeviceFingerprint(req); 

    const { accessToken, refreshToken: newRefreshToken } = await authService.rotateRefreshToken(refreshToken, deviceId);

    res.cookie("accessToken", accessToken,{
        httpOnly: true,
        secure: true,
        sameSite: "strict",
        maxAge: config.ACCESS_TOKEN_EXP_SEC * 1000
    }) 

    res.cookie("refreshToken", newRefreshToken,{
        httpOnly: true,
        secure: true,
        sameSite: "strict",
        maxAge: config.REFRESH_TOKEN_EXP_SEC * 1000
    })

    res.status(200).json({
        message: "Refresh token rotated successfully",
        success: true
    })
})

// module.exports = {
//     sendOTP
// }