import { Request, Response, NextFunction } from 'express';
import { forgotPasswordSchema, LoginSchema, resetPasswordSchema, SignUpSchema, UpdateUserProfileSchema } from '@repo/common';
import { AppError, ValidationError } from '../../errors/error';
import { errorDetails } from '../../utils/utils';
import { ZodObject, ZodRawShape, ZodType, ZodTypeAny } from 'zod';


class Validator{
  private constructor(){}

  public static validate<T>(body:Request<{},{},unknown>,parser:ZodType<T>){
    if(body === null || Object.keys(body).length === 0) {
      throw new ValidationError("Validation error","Request body cannot be empty");
    }
    const parsedData = parser.safeParse(body);
    if (!parsedData.success) {
      const messages = errorDetails(parsedData);
     throw new ValidationError("Validation error",messages);
    }
  }
}

 const createValidationMiddleware = (schema: ZodTypeAny) => {
  return async (req:Request,res:Response,next:NextFunction) =>{
    try {
      Validator.validate(req.body,schema);
      next();
    } catch (error) {
      console.log("error",error);
      if(error instanceof AppError) {
          return res.status(error.statusCode).json({type:error.status,message:error.details});
      }
      return res.status(500).json({type:"error",message:"Something went wrong"});
    }
  };
};


export const refreshTokenValidator = (req: Request, res: Response, next: NextFunction) => {
  const token = req.cookies?.refreshToken;

  if (!token || typeof token !== "string") {
    return res.status(401).json({
      status: "unauthorized",
      message: "Missing or invalid refresh token",
    });
  }
  next();
};



export const registerUserValidator = createValidationMiddleware(SignUpSchema);
export const loginUserValidator = createValidationMiddleware(LoginSchema);
export const updateUserProfileValidator = createValidationMiddleware(UpdateUserProfileSchema);
export const forgotPasswordValidator = createValidationMiddleware(forgotPasswordSchema);
export const resetPasswordValidator = createValidationMiddleware(resetPasswordSchema);