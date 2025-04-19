import { Request, Response } from 'express';
import { ApiResponse } from '../types/api_response.interface';

export interface IInvitation {
    inviteUserToWorkspace: (req: Request, res: Response) => Promise<Response<ApiResponse>>;
    getInvite: (req: Request, res: Response) => Promise<Response<ApiResponse>>;
    acceptInvite: (req: Request, res: Response) => Promise<Response<ApiResponse>>;
    cancelInvite: (req: Request, res: Response) => Promise<Response<ApiResponse>>;
    resendInvite: (req: Request, res: Response) => Promise<Response<ApiResponse>>;
};