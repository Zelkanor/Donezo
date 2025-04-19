import { Request, Response } from 'express';
import {  AuthApiResponse } from '../types/api_response.interface';
import { LoginResponse, SignUpResponse } from '@repo/common';

export interface IAuthController {
    registerUser: (req: Request, res: Response) => Promise<Response<AuthApiResponse<SignUpResponse>>>;
    loginUser: (req: Request, res: Response) => Promise<Response<AuthApiResponse<LoginResponse>>>;
    getRefreshToken: (req: Request, res: Response) => Promise<Response<AuthApiResponse>>;
    forgotPassword: (req: Request, res: Response) => Promise<Response<AuthApiResponse>>;
    resetPassword: (req: Request, res: Response) => Promise<Response<AuthApiResponse>>; 
    logoutUser: (req: Request, res: Response) => Promise<Response<AuthApiResponse>>;
};