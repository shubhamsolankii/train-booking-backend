const prisma = require("../config/prisma");
const { ConflictError, BadRequestError } = require("../utils/error");
const { verifyOtp } = require("../utils/otp");
const { generateAndStoreOtp } = require("../utils/otp");
const bcrypt = require("bcrypt");



exports.sendOTP = async(firstName, lastName, email, password) =>{

    const existingUser = await prisma.user.findUnique({
        where: {email}
    });

    if(existingUser){
        throw new ConflictError("User with this email already exists");
    }

    const hashedPassword = await bcrypt.hash(password, 12);
    const meta = { firstName, lastName, email, hashedPassword };

    const {otp , otpSessionId} = await generateAndStoreOtp(meta);

    // Return OTP in response instead of sending via email
    return {otpSessionId, otp};

}

exports.verifyOTP = async(otpSessionId, otp) =>{
    const meta = await verifyOtp(otp, otpSessionId);
    if(meta === null){
        throw new BadRequestError("Invalid OTP", "OTP_INVALID");
    }
    const user = await prisma.user.create({
        data:{
            firstName: meta.firstName,
            lastName: meta.lastName,
            email: meta.email,
            password: meta.hashedPassword,
            emailVerified: true
        }
    })

    return user;
}

