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
      const salt = await bcrypt.genSalt(10);
      const hashedPassword = await bcrypt.hash(body.password, salt);

      const deviceId = crypto.randomUUID();
   

      //Create user
      const user = await this.prisma.user.create({
        data: {
          email: body.email,
          password: hashedPassword,
          firstName: body.firstName,
          lastName: body.lastName,
          userName: body.userName,
          profileImageUrl: body.profileImageUrl,
          countryCode: body.countryCode,
          phoneNumber: body.phoneNumber,
        },
      });

       //Save deviceId in redis
         await RedisClient.getInstance().set(`session:${user.id}`, deviceId, 'EX', 60 * 60 * 24 * 7);
         await this.prisma.session.create({
          data: {
            userId: user.id,
            deviceId: deviceId,
          },
        });


      const jwtAccessPayload: JwtPayload = {
        id: user.id,
        deviceId: deviceId,
        iat: Math.floor(Date.now() / 1000),
      }

      const jwtRefreshPayload: JwtPayload = {
        id: user.id,
        deviceId: deviceId,
        iat: Math.floor(Date.now() / 1000),
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

      const deviceId = crypto.randomUUID();
      //Save deviceId in redis
      await RedisClient.getInstance().set(`session:${user.id}`, deviceId, 'EX', 60 * 60 * 24 * 7); 
      await this.prisma.session.deleteMany({
        where: {
          userId: user.id,
        },
      })
      await this.prisma.session.create({
        data: {
          userId: user.id,
          deviceId: deviceId,
        },
      });

      //Confgure JWT payload
      const jwtAccessPayload: JwtPayload = {
        id: user.id,
        deviceId: deviceId,
        iat: Math.floor(Date.now() / 1000),
      }

      const jwtRefreshPayload: JwtPayload = {
        id: user.id,
        deviceId: deviceId,
        iat: Math.floor(Date.now() / 1000),
      }

      //Generate token
      const accesToken = generateAccessToken(jwtAccessPayload);
      const refreshToken = generateRefreshToken(jwtRefreshPayload);

      //Send response
      const response:LoginResponse = {
        id: user.id,
        email: user.email,
        accessToken: accesToken,
      }
       res.cookie('refreshToken',refreshToken,{
          httpOnly: true,
          //secure: process.env.NODE_ENV === 'production',
          secure: false,
          sameSite: 'strict',
          maxAge: 60 * 60 * 24 * 7 * 1000, // 7 days
       });
       return res.status(200).json({status: "success",message: "User logged in successfully",data: response});
    } catch (error) {
      console.log("Error in registerUser: ", error);
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
      const sessionDevice = await RedisClient.getInstance().get(`session:${decoded.id}`);
      if(sessionDevice !== decoded.deviceId){
        throw new AuthError(AuthErrorCodes.INVALID_SESSION);
      }
    

      //Generate new token
      const jwtAccessPayload: JwtPayload = {
        id: decoded.id,
        deviceId: decoded.deviceId,
        iat: Math.floor(Date.now() / 1000),
      }

      const accesToken = generateAccessToken(jwtAccessPayload);

      //Send response
      return res.status(200).json({type: "success",message: "Token refreshed successfully",data:{accessToken: accesToken}});
    } catch (error) {
      console.log("Error in getRefreshToken: ", error);
      if(error instanceof AuthError){
        return res.status(error.statusCode).json({type: error.status,message: error.message});
      }
      return res.status(500).json({type: "server-error",message: "Internal server error"});
    }
  };


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
        await RedisClient.getInstance().del(`session:${decoded.id}`);
        await this.prisma.session.deleteMany({
          where: {
            userId: decoded.id,
          },
        });
        res.clearCookie('refreshToken');
        return res.status(200).json({type: "success",message: "User logged out successfully"});

    } catch (error) {
      console.log("Error in logoutUser: ", error);
      if(error instanceof AuthError){
        return res.status(error.statusCode).json({type: error.status,message: error.message});
      }
      return res.status(500).json({type: "server-error",message: "Internal server error"});
    }
   
  };
} 


