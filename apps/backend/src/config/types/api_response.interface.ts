import { AuthErrorCodes } from "../../errors/error";

export type ApiResponse<T = any> = {
    status: 'success' | 'error' ;
    message: string;
    data?: T ;
};

export type AuthApiResponse<T = any> = |{
    status: 'success';
    message: string;
    data?: T ;
}|{
      status: 'error';
      message: string;
      errorCode: AuthErrorCodes;
};

export interface JwtPayload {
    id: string;
    deviceId: string;
    iat: number;
  }

