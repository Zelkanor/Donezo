import { Request, Response } from 'express';
import { ApiResponse } from '../types/api_response.interface';
export interface IWorkspace {
    createWorkspace: (req: Request, res: Response) => Promise<Response<ApiResponse>>;
    getAllUserWorkspaces: (req: Request, res: Response) => Promise<Response<ApiResponse>>;
    getWorkspaceById: (req: Request, res: Response) => Promise<Response<ApiResponse>>;
    updateWorkspace: (req: Request, res: Response) => Promise<Response<ApiResponse>>;
    deleteWorkspace: (req: Request, res: Response) => Promise<Response<ApiResponse>>;
    getAllWorkspaceMembers: (req: Request, res: Response) => Promise<Response<ApiResponse>>;
    updateWorkspaceMemberRole: (req: Request, res: Response) => Promise<Response<ApiResponse>>;
    removeWorkspaceMember: (req: Request, res: Response) => Promise<Response<ApiResponse>>;
}