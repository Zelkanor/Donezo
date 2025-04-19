import {  UpdateUserProfileType } from '@repo/common';
import { Request, Response } from 'express';
import { PrismaInstance } from '../config/prisma_client';
import { AuthError, AuthErrorCodes } from '../errors/error';
import {PrismaClient} from '../../generated/prisma/client'

export class UserController {
    public static instance:UserController | null = null;
    private prisma: PrismaClient;
    private constructor() {
        this.prisma = PrismaInstance.getInstance();
    }

    public static getInstance(): UserController {
        if (!this.instance) {
            this.instance = new UserController();
        }
        return this.instance;
    }

    // @desc Get user profile
      // @route GET /api/v1/user/profile
      // @access Private
      public getUserProfile = async (req: Request, res: Response) => {
        try {
          const user = await this.prisma.user.findUnique({where:{id: req.user!.id},
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
     // @route PATCH /api/v1/user/profile
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
  // @route DELETE /api/v1/user/profile
  // @access Private
  public deleteUserProfile = async (req: Request, res: Response) => {};

    
}