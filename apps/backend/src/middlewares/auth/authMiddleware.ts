import { Request, Response, NextFunction } from 'express';
import jwt from 'jsonwebtoken';
import { RedisClient } from '../../config/redis_client';
import { JwtPayload } from '../../config/types/api_response.interface';
import { verifyToken } from '../../utils/utils';
import { AuthError, AuthErrorCodes } from '../../errors/error';




export const authMiddleware = async (req:Request,res:Response,next:NextFunction) =>{
    try {
        let authHeader = req.headers.authorization;
        if(!authHeader || !authHeader.startsWith("Bearer")){
            throw new AuthError(AuthErrorCodes.TOKEN_INVALID);
        }
        const token = authHeader.split(" ")[1];
        if(!token){
            throw new AuthError(AuthErrorCodes.TOKEN_INVALID);
        }
        const decoded = verifyToken(token,"access") as JwtPayload;
        const sessionKey = `session:${decoded.id}:${decoded.deviceId}`;
        const sessionData = await RedisClient.getInstance().get(sessionKey);
        if (!sessionData) {
            throw new AuthError(AuthErrorCodes.SESSION_EXPIRED);
        }
        const { ipAddress, userAgent, deviceId } = JSON.parse(sessionData);

        if (deviceId !== decoded.deviceId) {
            await RedisClient.getInstance().del(sessionKey);
            throw new AuthError(AuthErrorCodes.SUSPICIOUS_ACTIVITY);
        }

        // if (process.env.NODE_ENV === 'production') {
        //     if (ipAddress !== req.ip || userAgent !== req.headers['user-agent']) {
        //         await RedisClient.getInstance().del(sessionKey);
        //         throw new AuthError(AuthErrorCodes.SUSPICIOUS_ACTIVITY);
        //     }
        // }
        req.user ={
            id:decoded.id,
            deviceId:decoded.deviceId,
            iat:decoded.iat,
        };
        next();

    } catch (error) {
        console.error("error",error);
        res.clearCookie('accessToken');
        res.clearCookie('refreshToken');
        if(error instanceof jwt.TokenExpiredError){
            return res.status(401).json({status:"auth/token-expired",message: `Token expired at ${error.expiredAt}`});
        }
        if(error instanceof AuthError){
            return res.status(error.statusCode).json({status:error.status,message:error.message});
        }
        return res.status(401).json({status:"auth/unauthorized",message:"Authentication failed"});
    }
}

