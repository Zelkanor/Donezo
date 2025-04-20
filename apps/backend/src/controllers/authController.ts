import bcrypt from 'bcryptjs';
import { ForgotPasswordType, LoginResponse, LoginType, ResetPasswordType, SignUpResponse, SignUpType } from '@repo/common';
import { Request, Response } from 'express';
import { PrismaInstance } from '../config/prisma_client';
import { AuthError, AuthErrorCodes } from '../errors/error';
import {PrismaClient} from '../../generated/prisma/client'
import { IAuthController } from '../config/interfaces/auth.interface';
import { ApiResponse, AuthApiResponse, JwtPayload } from '../config/types/api_response.interface';
import { RedisClient } from '../config/redis_client';
import { generateAccessToken, generatePasswordResetToken, generateRefreshToken, sendMail, verifyPasswordResetToken, verifyToken } from '../utils/utils';
import { generatePasswordResetEmail } from '../config/email/mail_templates';



export class AuthController implements IAuthController{
 private prisma: PrismaClient;
 private static instance: AuthController | null = null;
 private constructor(){
    this.prisma = PrismaInstance.getInstance();
  this.registerUser = this.registerUser.bind(this);
  this.loginUser = this.loginUser.bind(this);
  this.getRefreshToken = this.getRefreshToken.bind(this);
  this.forgotPassword = this.forgotPassword.bind(this);
  this.logoutUser = this.logoutUser.bind(this);
  this.resetPassword = this.resetPassword.bind(this);
  this.forgotPassword = this.forgotPassword.bind(this);
  }
  

  public static getInstance(): AuthController {
    if (!this.instance) {
      this.instance = new AuthController();
    }
    return this.instance;
  }


  // @desc Register a new user
  // @route POST /api/v1/auth/register
  // @access Public
  async registerUser(req:Request, res: Response):Promise<Response<AuthApiResponse<SignUpResponse>>> { 

    const body: SignUpType = req.body;

  try {
      //Check if user already exists
      const userExists = await this.prisma.user.findUnique({
        where: {
          email: body.email,
        },
      });
      if (userExists) {
        throw new AuthError(AuthErrorCodes.USER_ALREADY_EXISTS)
      }

      //Hash password
      const salt = await bcrypt.genSalt(12);
      const hashedPassword = await bcrypt.hash(body.password, salt);

      const deviceId = crypto.randomUUID();
      const ipAddress = req.ip; // Get the IP address from the request
      const userAgent = req.headers['user-agent'] || 'unknown';
   

      //Create user
      const user = await this.prisma.$transaction(async (prisma) => {
        // Create user and session in DB
        const user = await prisma.user.create({
            data: {
                email: body.email,
                password: hashedPassword,
                firstName: body.firstName,
                lastName: body.lastName,
                userName: body.userName,
                profileImageUrl: body.profileImageUrl,
                countryCode: body.countryCode,
                phoneNumber: body.phoneNumber,
                sessions: {
                    create: {
                        deviceId,
                        ipAddress,
                        userAgent
                    }
                }
            },
            include: { sessions: true }
        });

        // Create Redis session
     await RedisClient.getInstance()
            .multi()
            .set(
                `session:${user.id}:${deviceId}`,
                JSON.stringify({
                    ipAddress,
                    userAgent,
                    deviceId,
                    lastActiveAt: new Date().toISOString()
                }),
                'EX',
                60 * 60 * 24 * 7 // 7 days
            )
            .exec();
        return user;
    });

      const jwtAccessPayload: JwtPayload = {
        id: user.id,
        deviceId: deviceId,
        iat: Math.floor(Date.now() / 1000),
        isRefreshToken: false,
      }

      const jwtRefreshPayload: JwtPayload = {
        ...jwtAccessPayload
      }

      //Generate token
      const accesToken = generateAccessToken(jwtAccessPayload);
      const refreshToken = generateRefreshToken(jwtRefreshPayload);

      //Send response
      const response:SignUpResponse = {
        id: user.id,
        email: user.email,
        accessToken: accesToken,
      }
      res.cookie('refreshToken',refreshToken,{
        httpOnly: true,
        //secure: process.env.NODE_ENV === 'production',
        secure: false,
        sameSite: 'strict',
        path:'/api/v1/auth/refresh-token',
        //domain: process.env.COOKIE_DOMAIN,
        maxAge: 60 * 60 * 24 * 7 * 1000, // 7 days
     });
      return res.status(201).json({type: "success",message: "User registered successfully",data: response});

  } catch (error) {
        console.log("Error in registerUser: ", error);
        if(error instanceof AuthError){
          return res.status(error.statusCode).json({type: error.status,message: error.message});
        }
        return res.status(500).json({type: "server-error",message: "Internal server error"});
      }
}


  // @desc Login user
  // @route POST /api/v1/auth/login   
  // @access Public
  async loginUser(req: Request, res: Response):Promise<Response<AuthApiResponse<LoginResponse>>> {
    const body:LoginType = req.body;
    try {
      const user = await this.prisma.user.findUnique({where:{email:body.email}});
      if(!user){
        throw new AuthError(AuthErrorCodes.INVALID_CREDENTIALS);
      }

      //Check password
      const isMatch = await bcrypt.compare(body.password, user.password);
      if(!isMatch) {
        throw new AuthError(AuthErrorCodes.INVALID_CREDENTIALS);
      }

      // Invalidate all previous sessions for single-device login
      await this.prisma.session.deleteMany({
        where: {
          userId: user.id,
        },
      });
       // Clear all Redis sessions for this user
       const keys = await RedisClient.getInstance().keys(`session:${user.id}:*`);
       if (keys.length > 0) {
           await RedisClient.getInstance().del(keys);
       }



       //Create new session
      const deviceId = crypto.randomUUID();
      const ipAddress = req.ip; // Get the IP address from the request
      const userAgent = req.headers['user-agent'] || 'unknown';
      //Save deviceId in redis
      await RedisClient.getInstance().set(`session:${user.id}:${deviceId}`, 
        JSON.stringify({
          ipAddress,
          userAgent,
          deviceId,
          lastActiveAt: new Date().toISOString(),
        }), 'EX', 60 * 60 * 24 * 7); 
      
      await this.prisma.session.create({
        data: {
          userId: user.id,
          deviceId: deviceId,
          ipAddress,
          userAgent
        },
      });

      //Confgure JWT payload
      const jwtAccessPayload: JwtPayload = {
        id: user.id,
        deviceId: deviceId,
        iat: Math.floor(Date.now() / 1000),
        isRefreshToken: false,
      }

      const jwtRefreshPayload: JwtPayload = {
        ...jwtAccessPayload,
        isRefreshToken: true,
      }

      //Generate token
      const accessToken = generateAccessToken(jwtAccessPayload);
      const refreshToken = generateRefreshToken(jwtRefreshPayload);

      //Send response
      const response:LoginResponse = {
        id: user.id,
        email: user.email,
        accessToken
      }
       res.cookie('refreshToken',refreshToken,{
          httpOnly: true,
          //secure: process.env.NODE_ENV === 'production',
          secure: false,
          sameSite: 'strict',
          maxAge: 60 * 60 * 24 * 7 * 1000, // 7 days
          path: '/api/v1/auth/refresh-token',
          //domain: process.env.COOKIE_DOMAIN
       });
       return res.status(200).json({status: "success",message: "User logged in successfully",data: response});
    } catch (error) {
      console.log("Error in registerUser: ", error);
      res.clearCookie('refreshToken');
      if(error instanceof AuthError){
        return res.status(error.statusCode).json({type: error.status,message: error.message});
      }
      return res.status(500).json({type: "server-error",message: "Internal server error"});
    }
  }


  // @desc Refresh token
  // @route POST /api/v1/auth/refresh-token
  // @access Public
  public async getRefreshToken(req: Request, res: Response):Promise<Response<ApiResponse>>{
    try {
      //Verify refresh token
      const decoded = verifyToken(req.cookies.refreshToken,"refresh");
      if (!decoded.isRefreshToken) {
        throw new AuthError(AuthErrorCodes.TOKEN_INVALID);
    }

      //Check if session exists in redis
      let sessionValid = false;
      try {
         const sessionData = await RedisClient.getInstance().get(`session:${decoded.id}:${decoded.deviceId}`);
          if (sessionData) {
            const {ipAddress,deviceId,userAgent} = JSON.parse(sessionData);
            const maxSessionAge = 7 * 24 * 60 * 60 * 1000;
            if (ipAddress !== req.ip || userAgent !== req.headers['user-agent'] || deviceId !== decoded.deviceId) {
              // Potential security issue - force reauthentication
              await RedisClient.getInstance().del(`session:${decoded.id}:${decoded.deviceId}`);
              throw new AuthError(AuthErrorCodes.SUSPICIOUS_ACTIVITY);
          } else {
            sessionValid = true;
          }
          }
      } catch (redisError) {
        console.warn('Redis error:', redisError);
        if(redisError instanceof AuthError) {
          res.clearCookie('refreshToken');
          return res.status(redisError.statusCode).json({type: redisError.status,message: redisError.message});
        }
        // 2. Fallback to Prisma if Redis fails
        try {
          const dbSession = await this.prisma.session.findFirst({
            where: {
                userId: decoded.id,
                deviceId: decoded.deviceId,
            }
        });
          if (dbSession) {
            if (dbSession.ipAddress !== req.ip || dbSession.userAgent !== req.headers['user-agent'] || dbSession.deviceId !== decoded.deviceId) {
              // Potential security issue - force reauthentication
              await RedisClient.getInstance().del(`session:${decoded.id}:${decoded.deviceId}`);
              await this.prisma.session.deleteMany({
                where: {
                  userId: decoded.id,
                  deviceId: decoded.deviceId
                }
              });
              throw new AuthError(AuthErrorCodes.SUSPICIOUS_ACTIVITY);
          } else {
            sessionValid = true;
          }
          }
        } catch (dbError) {
          console.error("Both Redis and DB failed", dbError);
          // 3. If both stores fail, implement emergency protocol
          return this.handleDegradedRefresh(res, decoded);
        }
      }
     
      if (!sessionValid) {
        throw new AuthError(AuthErrorCodes.SESSION_EXPIRED);
    }
       
      //Generate new token
      const jwtAccessPayload: JwtPayload = {
        id: decoded.id,
        deviceId: decoded.deviceId,
        iat: Math.floor(Date.now() / 1000),
        isRefreshToken: false,
      }
      const jwtRefreshPayload: JwtPayload = {
        ...jwtAccessPayload,
        isRefreshToken: true,
      }


      const accesToken = generateAccessToken(jwtAccessPayload);
      const refreshToken = generateRefreshToken(jwtRefreshPayload);
      res.cookie('refreshToken',refreshToken,{
        httpOnly: true,
        //secure: process.env.NODE_ENV === 'production',
        secure: false,
        sameSite: 'strict',
        maxAge: 60 * 60 * 24 * 7 * 1000, // 7 days
        path: '/api/v1/auth/refresh-token',
        //domain: process.env.COOKIE_DOMAIN
     });
      //Send response
      return res.status(200).json({type: "success",message: "Token refreshed successfully",data:{accessToken: accesToken}});
    } catch (error) {
      console.error("Error in getRefreshToken: ", error);
      if(error instanceof AuthError){
        if (error.status === AuthErrorCodes.SESSION_EXPIRED) {
          res.clearCookie('refreshToken');
      }
        return res.status(error.statusCode).json({type: error.status,message: error.message});
      }
      return res.status(500).json({type: "server-error",message: "Internal server error"});
    }
  };

  private handleDegradedRefresh(res: Response, decoded: JwtPayload): Response {
    // Emergency short-lived token (5-15 minutes) with limited scope
    const emergencyToken = generateAccessToken({
        id: decoded.id,
        deviceId: decoded.deviceId,
        iat: Math.floor(Date.now() / 1000),
        isRefreshToken: false,
    }, true); // Short expiry

    // Log the incident
    // monitoring.log('AUTH_DEGRADED', {
    //     userId: decoded.id,
    //     deviceId: decoded.deviceId
    // });

    return res.status(200)
        .set('X-Auth-Mode', 'degraded')
        .json({
            type: "warning",
            message: "Service temporarily degraded - please reauthenticate later",
            data: {
                accessToken: emergencyToken,
                expiresIn: "15 minutes"
            }
        });
}

  // @desc Forgot password
  // @route POST /api/v1/auth/forgot-password
  // @access Public
  public async forgotPassword (req: Request, res: Response): Promise<Response<ApiResponse>>{
    const body:ForgotPasswordType = req.body;
    try {
      const user = await this.prisma.user.findUnique({ where: { email:body.email }});

      if (!user) {
        throw new AuthError(AuthErrorCodes.USER_NOT_FOUND);
      }
      //Generate password reset token
      const passwordResetToken = generatePasswordResetToken(user.id);
      await RedisClient.getInstance().set(`reset-token:${user.id}`, passwordResetToken, 'EX', 60 * 15); // 15 minutes
      //SEND EMAIL
      await sendMail({
        from: process.env.EMAIL_FROM as string,
        to: body.email,
        subject: 'Password Reset',
        html: generatePasswordResetEmail(user.firstName, passwordResetToken),
      });
      return res.status(200).json({ status: 'success', message: 'Password reset link sent to email' });
    } catch (error) {
      console.error('Error in forgotPassword:', error);
      if (error instanceof AuthError) {
        return res.status(error.statusCode).json({ type: error.status, message: error.message });
      }
      return res.status(500).json({ type: 'server-error', message: 'Internal server error' });
    }
  };

  // @desc Reset password
  // @route POST /api/v1/auth/reset-password
  // @access Public
  public async resetPassword (req: Request, res: Response): Promise<Response<ApiResponse>>{
    const body: ResetPasswordType = req.body;
   try {
    const payload = verifyPasswordResetToken(body.token);
    const storedToken = await RedisClient.getInstance().get(`reset-token:${payload.id}`);

    if (!storedToken || storedToken !== body.token) {
      throw new AuthError(AuthErrorCodes.INVALID_OR_EXPIRED_TOKEN);
    }
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(body.password, salt);

    await this.prisma.user.update({
      where: { id: payload.id },
      data: { password: hashedPassword },
    });
    await RedisClient.getInstance().del(`reset-token:${payload.id}`); // Delete the token from Redis
    return res.status(200).json({ type: 'success', message: 'Password reset successful' });
   } catch (error) {
    console.error('Error in resetPassword:', error);
    if (error instanceof AuthError) {
      return res.status(error.statusCode).json({ status: error.status, message: error.message });
    }
    return res.status(500).json({ status: 'server-error', message: 'Internal server error' });
   }
  };

  // @desc Logout user
  // @route POST /api/v1/auth/logout
  // @access Private
  public async logoutUser (req: Request, res: Response): Promise<Response<ApiResponse>>{
    try {
        const decoded = verifyToken(req.cookies.refreshToken,"refresh");
        await RedisClient.getInstance().del(`session:${decoded.id}:${decoded.deviceId}`);
        await this.prisma.session.deleteMany({
          where: {
            userId: decoded.id,
            deviceId: decoded.deviceId,
          },
        });
        res.clearCookie('refreshToken', {
          path: '/api/v1/auth/refresh-token',
          //domain: process.env.COOKIE_DOMAIN
      });
        return res.status(200).json({type: "success",message: "User logged out successfully"});

    } catch (error) {
      console.log("Error in logoutUser: ", error);
      res.clearCookie('refreshToken');
      if(error instanceof AuthError){
        return res.status(error.statusCode).json({type: error.status,message: error.message});
      }
      return res.status(500).json({type: "server-error",message: "Internal server error"});
    }
   
  };
} 


