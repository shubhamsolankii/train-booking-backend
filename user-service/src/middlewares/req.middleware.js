const logger = require('../config/logger');

const regLogger = (req, res, next) =>{
    logger.debug(`[${req.method}] [${req.originalUrl}]`);
    const start = Date.now();

    res.on('finish', () =>{
        const duration = Date.now() - start;
        logger.info(`[${req.method}] [${req.originalUrl}] -  [${res.statusCode}] [${duration}ms]`);

    })

    next();
}

export { regLogger};