import { Request, Response, NextFunction } from 'express';
import jwt from 'jsonwebtoken';

interface JwtPayload {
    id: string;
    sessionId: string;
    iat: number;
    exp: number;
  }


export const authMiddleware = async (req:Request,res:Response,next:NextFunction) =>{
    try {
        let token = req.headers.authorization;
        if(!token || !token.startsWith("Bearer")){
            return res.status(401).json({type:"error",message:"Unauthorized"});
        }
        token = token.split(" ")[1];
        if(!token){
            return res.status(401).json({type:"error",message:"Unauthorized"});
        }
        const decoded = jwt.verify(token,process.env.JWT_ACCESS_SECRET) as JwtPayload;
        if(!decoded){
            return res.status(401).json({type:"error",message:"Unauthorized"});
        }   
        
        req.user ={
            id:decoded.id,
            sessionId:decoded.sessionId,
            iat:decoded.iat,
            exp:decoded.exp
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

