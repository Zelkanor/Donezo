import { Router } from "express";
import { AuthController } from "../controllers/authController";
import { authMiddleware } from "../middlewares/auth/authMiddleware";
import rateLimit from "express-rate-limit";
import { forgotPasswordValidator, loginUserValidator, refreshTokenValidator, registerUserValidator, resetPasswordValidator } from "../middlewares/validators/validator";
const authRouter:Router = Router();

const AuthInstance = AuthController.getInstance();

const forgotPasswordLimiter = rateLimit({
    validate: {ip:false,xForwardedForHeader:false},
    windowMs: 15 * 60 * 1000, 
    max: 5, 
    message: {type:"error" , msg:  `Too many attempts. Try again in 15 min` },
    skip: (req) => req.ip === '::1' // Skip for localhost
});
const resetPassLimiter = rateLimit({
    validate: {ip:false,xForwardedForHeader:false},
    windowMs: 15 * 60 * 1000, 
    max: 4, 
    message: {type:"error" , msg:  `Too many attempts. Try again in 15 min` },
    skip: (req) => req.ip === '::1' // Skip for localhost
});

authRouter.post("/register",registerUserValidator,AuthInstance.registerUser);
authRouter.post("/login",loginUserValidator, AuthInstance.loginUser);
authRouter.post("/forgot-password",forgotPasswordLimiter,forgotPasswordValidator, AuthInstance.forgotPassword);
authRouter.post("/reset-password",resetPassLimiter,resetPasswordValidator, AuthInstance.resetPassword);
authRouter.post("/refresh-token",refreshTokenValidator, AuthInstance.getRefreshToken);
authRouter.post("/logout", authMiddleware, AuthInstance.logoutUser);


export default authRouter;