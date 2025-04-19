import { Request, Response, NextFunction } from 'express';
import jwt from 'jsonwebtoken';
import { RedisClient } from '../../config/redis_client';
import { JwtPayload } from '../../config/types/api_response.interface';
import { verifyToken } from '../../utils/utils';




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
        const sessionDevice = await RedisClient.getInstance().get(`session:${decoded.id}`);
        if(!sessionDevice || sessionDevice !== decoded.deviceId){
            return res.status(401).json({status:"error",message:"Session Invalidated"});

        }
        req.user ={
            id:decoded.id,
            deviceId:decoded.deviceId,
            iat:decoded.iat,
        };
        next();
    } catch (error) {
        console.log("error",error);
        if(error instanceof jwt.TokenExpiredError){
            return res.status(401).json({type:"auth/token-expired",message: `Token expired at ${error.expiredAt}`});
        }
        return res.status(401).json({type:"error",message:"Unauthorized"});
    }
}

