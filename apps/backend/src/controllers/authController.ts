import jwt from 'jsonwebtoken';
import bcrypt from 'bcryptjs';
import { JWTPayload, LoginResponse, LoginType, SignUpResponse, SignUpType, UpdateUserProfileType } from '@repo/common';
import { Request, Response } from 'express';
import { PrismaInstance } from '../config/prisma_client';
import { AuthError, AuthErrorCodes } from '../errors/error';
import {PrismaClient} from '../../generated/prisma/client'



//Generate JWT Access token
export const generateAccessToken = (payload:JWTPayload) => {
  return jwt.sign(payload, process.env.JWT_ACCESS_SECRET as string, {
    expiresIn: '10m',
  });
};


//Generate JWT Refresh token
export const generateRefreshToken = (payload:JWTPayload) => {
  return jwt.sign(payload, process.env.JWT_REFRESH_SECRET as string, {
    expiresIn: '30d',
  });
};


export class AuthController{
 private prisma: PrismaClient;
 private static instance: AuthController | null = null;
 private constructor(){
    this.prisma = PrismaInstance.getInstance();
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
  public registerUser = async (req:Request, res: Response) => {

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

      const jwtAccessPayload: JWTPayload = {
        id: user.id,
        sessionId: "dasdasd",
        iat: Math.floor(Date.now() / 1000),
      }

      const jwtRefreshPayload: JWTPayload = {
        id: user.id,
        sessionId: "dasdasd",
        iat: Math.floor(Date.now() / 1000),
      }

      //TODO: Save refresh token in database and sessions
      //Generate token
      const accesToken = generateAccessToken(jwtAccessPayload);
      const refreshToken = generateRefreshToken(jwtRefreshPayload);

      //Send response
      const response:SignUpResponse = {
        id: user.id,
        accessToken: accesToken,
        refreshToken: refreshToken,
      }
      return res.status(201).json({type: "success",message: "User registered successfully",data: response});

  } catch (error) {
        console.log("Error in registerUser: ", error);
        if(error instanceof AuthError){
          return res.status(error.statusCode).json({type: error.status,message: error.message});
        }
        return res.status(500).json({type: "server-error",message: "Internal server error"});
      }
};


  // @desc Login user
  // @route POST /api/v1/auth/login   
  // @access Public
  public loginUser = async (req: Request, res: Response) => {
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

      //Generate token
      const jwtAccessPayload: JWTPayload = {
        id: user.id,
        sessionId: "dasdasd",
        iat: Math.floor(Date.now() / 1000),
      }

      const jwtRefreshPayload: JWTPayload = {
        id: user.id,
        sessionId: "dasdasd",
        iat: Math.floor(Date.now() / 1000),
      }

      //TODO: Save refresh token in database and sessions
      //Generate token
      const accesToken = generateAccessToken(jwtAccessPayload);
      const refreshToken = generateRefreshToken(jwtRefreshPayload);

      //Send response
      const response:LoginResponse = {
        id: user.id,
        accessToken: accesToken,
        refreshToken: refreshToken,
      }

      return res.status(200).json({type: "success",message: "User logged in successfully",data: response});
    } catch (error) {
      console.log("Error in registerUser: ", error);
      if(error instanceof AuthError){
        return res.status(error.statusCode).json({type: error.status,message: error.message});
      }
      return res.status(500).json({type: "server-error",message: "Internal server error"});
    }
  }


  // @desc Get user profile
  // @route GET /api/v1/auth/profile
  // @access Private
  public getUserProfile = async (req: Request, res: Response) => {
    try {
      if(!req.user) {
        throw new AuthError(AuthErrorCodes.UNAUTHORIZED);
      }
      const user = await this.prisma.user.findUnique({where:{id: req.user.id},
      select:{
        id: true,
        email: true,
        firstName: true,
        lastName: true,
        profileImageUrl: true,
        countryCode: true,
        phoneNumber: true,
        emailVerified: true,
      }
      });
      if(!user) {
       throw new AuthError(AuthErrorCodes.USER_NOT_FOUND);
      }
      res.json({type: "success",message: "User profile fetched successfully",data: user});
    } catch (error) {
      console.log("Error in fetching user Profile: ", error);
      if(error instanceof AuthError){
        return res.status(error.statusCode).json({type: error.status,message: error.message});
      }
      return res.status(500).json({type: "server-error",message: "Internal server error"});
    }
  };

  // @desc Update user profile
  // @route PUT /api/v1/auth/profile
  // @access Private
  public updateUserProfile = async (req: Request, res: Response) => {
    const body:UpdateUserProfileType = req.body;
    try {
      if(!req.user) {
        throw new AuthError(AuthErrorCodes.UNAUTHORIZED);
      }
      const user = await this.prisma.user.update({
        where: { id: req.user.id },
        data: {
          userName: body.userName,
          countryCode: body.countryCode,
          phoneNumber: body.phoneNumber,
        },
      });
      res.json({type: "success",message: "User profile updated successfully"});
    } catch (error) {
      console.log("Error in fetching user Profile: ", error);
      if(error instanceof AuthError){
        return res.status(error.statusCode).json({type: error.status,message: error.message});
      }
      return res.status(500).json({type: "server-error",message: "Internal server error"});
    }
  };


  // @desc Delete user profile
  // @route DELETE /api/v1/auth/profile
  // @access Private
  public deleteUserProfile = async (req: Request, res: Response) => {};


  // @desc Refresh token
  // @route POST /api/v1/auth/refresh-token
  // @access Public
  public getRefreshToken = async (req: Request, res: Response) => {};

  // @desc Forgot password
  // @route POST /api/v1/auth/forgot-password
  // @access Public
  public forgotPassword = async (req: Request, res: Response) => {};
} 


