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
            return res.status(401).json({status:"error",message:"Missing or malformed token"});
        }
        const token = authHeader.split(" ")[1];
        if(!token){
            return res.status(401).json({status:"error",message:"Unauthorized"});
        }
        const decoded = verifyToken(token,"access") as JwtPayload;
        const sessionDevice = await RedisClient.getInstance().get(`session:${decoded.id}:${decoded.deviceId}`);
        if(sessionDevice ){
            const data = JSON.parse(sessionDevice);
            if(!data && data.deviceId !== decoded.deviceId){
                await RedisClient.getInstance().del(`session:${decoded.id}:${decoded.deviceId}`);
                throw new AuthError(AuthErrorCodes.INVALID_SESSION);
            }
            req.user ={
                id:decoded.id,
                deviceId:decoded.deviceId,
                iat:decoded.iat,
            };
            next();
        } else {
            await RedisClient.getInstance().del(`session:${decoded.id}:${decoded.deviceId}`);
            throw new AuthError(AuthErrorCodes.INVALID_SESSION);
        }
       
    } catch (error) {
        console.log("error",error);
        res.clearCookie('refreshToken');
        if(error instanceof jwt.TokenExpiredError){
            return res.status(401).json({status:"auth/token-expired",message: `Token expired at ${error.expiredAt}`});
        }
        if(error instanceof AuthError){
            return res.status(error.statusCode).json({status:error.status,message:error.message});
        }
        return res.status(401).json({status:"error",message:"Unauthorized"});
    }
}

