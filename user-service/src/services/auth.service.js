const prisma = require("../config/prisma");
const {redis} = require("../config/redis");
const { generateAccessToken, generateRefreshToken, verifyRefreshToken } = require("../utils/auth");
const { ConflictError, BadRequestError, NotFoundError, ForbiddenError } = require("../utils/error");
const { verifyOtp } = require("../utils/otp");
const { generateAndStoreOtp } = require("../utils/otp");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const { config } = require("../config");

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


exports.login = async(email, password, deviceId) =>{

    const doesUserExist = await prisma.user.findUnique({
        where: {email}
    });

    if(!doesUserExist){
        throw new NotFoundError("User with this email does not exist");
    }

    const doesPasswordMatch = await bcrypt.compare(password, doesUserExist.password);

    if(!doesPasswordMatch){
        throw new BadRequestError("Invalid password");
    }

    const accessToken = await generateAccessToken(doesUserExist.id);

    const refreshToken = await generateRefreshToken(doesUserExist.id);

    const {jti} = jwt.decode(refreshToken);

    await redis.set(`refresh:${doesUserExist.id}:${deviceId}`, jti, 'EX', config.REFRESH_TOKEN_EXP_SEC);
    
    const {password: _password, ...safeUser} = doesUserExist;

    await redis.set(`user:${doesUserExist.id}`, JSON.stringify(safeUser), 'EX', config.REDIS_USER_TTL);

    return {accessToken, refreshToken, loggedInUser: safeUser};

}

exports.rotateRefreshToken = async(refreshToken, deviceId) => {
   const payload = verifyRefreshToken(refreshToken);
   
   const {id: userId, jti: tokenJti} = payload;

   console.log(`Rotating refresh token for userId: ${userId}, deviceId: ${deviceId}, tokenJti: ${tokenJti}`);

   const storedJti = await redis.get(`refresh:${userId}:${deviceId}`);

   if(!storedJti){
        throw new ForbiddenError("Refresh token not found. Please login again.");
   }

   if(storedJti !== tokenJti){
        await redis.del(`refresh:${userId}:${deviceId}`);
        throw new ForbiddenError("Refresh token does not match. Please login again.");
   }

   const newAccessToken = await generateAccessToken(userId);
   const newRefreshToken = await generateRefreshToken(userId);
   const {jti: newJti} = jwt.decode(newRefreshToken);   
   await redis.set(`refresh:${userId}:${deviceId}`, newJti, 'EX', config.REFRESH_TOKEN_EXP_SEC);

   return { accessToken: newAccessToken, refreshToken: newRefreshToken};

}