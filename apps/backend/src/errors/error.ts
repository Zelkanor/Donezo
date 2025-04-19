export class AppError extends Error {
    public readonly status: string;
    public readonly statusCode: number;
    public readonly details?: unknown;
  
    constructor(status:string,message: string, statusCode: number = 500, details?: any) {
      super(message);
  
      Object.setPrototypeOf(this, new.target.prototype); // restore prototype chain

      this.status = status;
      this.statusCode = statusCode;
      this.details = details;
  
      Error.captureStackTrace(this);
    }
}

export class ValidationError extends AppError {
    constructor(message: string, details?: any) {
      super('input-error', message, 400, details);
    }
  }
export class EmailSendError extends AppError {
    constructor(message: string, details?: any) {
      super('email-error', message, 500, details);
    }
  };


export enum AuthErrorCodes {
  USER_ALREADY_EXISTS = "auth/user-already-exist",
  USER_NOT_FOUND = "auth/user-not-found",
  INVALID_CREDENTIALS = "auth/invalid-credentials",
  UNAUTHORIZED = "auth/unauthorized",
  TOKEN_EXPIRED = "auth/token-expired",
  TOKEN_INVALID = "auth/token-invalid",
  INVALID_SESSION = "auth/invalid-session",
  INVALID_OR_EXPIRED_TOKEN = "auth/invalid-or-expired-token",
}

export class AuthError extends AppError {
  constructor(code: AuthErrorCodes,details?:any){
    const {message, statusCode} = AuthError.mapCodeToMessageAndStatus(code);
    super(code, message, statusCode,details);
  }
  private static mapCodeToMessageAndStatus(code: AuthErrorCodes): { message: string; statusCode: number } {
    switch (code) {
      case AuthErrorCodes.USER_ALREADY_EXISTS:
        return { message: "User already exists", statusCode: 409 };
      case AuthErrorCodes.USER_NOT_FOUND:
        return { message: "User not found", statusCode: 404 };
      case AuthErrorCodes.INVALID_CREDENTIALS:
        return { message: "Invalid email or password", statusCode: 401 };
      case AuthErrorCodes.UNAUTHORIZED:
        return { message: "Unauthorized access", statusCode: 403 };
      case AuthErrorCodes.TOKEN_EXPIRED:
        return { message: "Token has expired", statusCode: 401 };
      case AuthErrorCodes.TOKEN_INVALID:
        return { message: "Token is invalid", statusCode: 401 };
      case AuthErrorCodes.INVALID_SESSION:
        return { message: "Session is invalid", statusCode: 401 };
      case AuthErrorCodes.INVALID_OR_EXPIRED_TOKEN:
        return { message: "Invalid or expired token", statusCode: 401 };
      default:
        return { message: "Authentication error", statusCode: 401 };
    }
  }
}