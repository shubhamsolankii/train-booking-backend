const { config } = require("../config");
const { TooManyRequestsError, BadRequestError } = require("./error");
const otpGenerator = require("otp-generator");
const {redis} = require("../config/redis");
const crypto = require("crypto");
const logger = require("../config/logger");


const RATE_MAX =  parseInt(config.OTP_RATE_MAX_PER_HOUR || '5', 10);
const ATTEMPT_MAX = parseInt(config.OTP_MAX_VERIFY_ATTEMPTS || '5', 10);
const HMAC_SECRET = config.OTP_HMAC_SECRET
const OTP_TTL = parseInt(config.OTP_TTL_SECONDS || '300', 10); // 5 minutes


function hmacFor(email, otp) {
    logger.info(`Generating HMAC for email: ${email} and otp: ${otp}`);
    return crypto.createHmac('sha256', HMAC_SECRET)
        .update(`${email}:${otp}`)
        .digest('hex');
}

async function generateAndStoreOtp(meta) {
    const rateKey = `otp:rate:${meta.email}`;
    const sentCount = parseInt(await redis.get(rateKey) || '0', 10);

    if(sentCount >= RATE_MAX){
        throw new TooManyRequestsError("Too many OTP requests. Please try again later.", "OTP_RATE_LIMIT");
    }

    const otp = otpGenerator.generate(6, {
        upperCaseAlphabets: false,
        lowerCaseAlphabets: false,
        specialChars: false,
    })

    const otpSessionId = crypto.randomUUID();
    const hashedOtp = hmacFor(meta.email, otp);

    await redis.set(`otp:session:${otpSessionId}`, JSON.stringify({
        meta,
        hashedOtp
    }), 'EX', OTP_TTL);

    await redis.incr(rateKey);
    await redis.expire(rateKey, 3600); // 1 hour
    return {otp, otpSessionId};

}

async function verifyOtp(otp, otpSessionId){
        const sessionData = await redis.get(`otp:session:${otpSessionId}`);
        if(!sessionData){
            throw new BadRequestError("Invalid OTP session");
        }

        const {meta, hashedOtp: storedHashedOtp} = JSON.parse(sessionData);

        const attemptsKey = `otp:attempts:${meta.email}`;
        const attemptsCount = parseInt(await redis.get(attemptsKey) || '0', 10);

        if(attemptsCount >= ATTEMPT_MAX){
            throw new TooManyRequestsError("Too many OTP verification attempts. Please request a new OTP.", "OTP_VERIFY_RATE_LIMIT");
        }

        const hashedOtp = hmacFor(meta.email, otp);
        logger.debug(`Comparing stored OTP: ${storedHashedOtp} with hashed OTP: ${hashedOtp} for email: ${meta.email}`);
        if(crypto.timingSafeEqual(Buffer.from(storedHashedOtp), Buffer.from(hashedOtp))){
            await redis.del(`otp:session:${otpSessionId}`, attemptsKey);
            await redis.del(`otp:rate:${meta.email}`);
            return meta;
        }
        else{
            await redis.incr(attemptsKey);
            await redis.expire(attemptsKey, config.OTP_TTL);
            return null;
        }
}

module.exports = {
    generateAndStoreOtp,
    verifyOtp
}
