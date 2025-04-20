import { Router } from "express";
import { AuthController } from "../controllers/authController";
import { authMiddleware } from "../middlewares/auth/authMiddleware";
import rateLimit from "express-rate-limit";
import { forgotPasswordValidator, loginUserValidator, refreshTokenValidator, registerUserValidator, resetPasswordValidator } from "../middlewares/validators/validator";
const authRouter:Router = Router();

const AuthInstance = AuthController.getInstance();

const authLimiter = rateLimit({
    validate: {ip:false,xForwardedForHeader:false},
    windowMs: 5 * 60 * 1000, 
    max: 7, 
    message: {type:"error" , msg: "Too many login attempts. Try again later." },
});

authRouter.use(authLimiter);
authRouter.post("/register",registerUserValidator,AuthInstance.registerUser);
authRouter.post("/login",loginUserValidator, AuthInstance.loginUser);
authRouter.post("/forgot-password",forgotPasswordValidator, AuthInstance.forgotPassword);
authRouter.post("/reset-password",resetPasswordValidator, AuthInstance.resetPassword);
authRouter.post("/refresh-token",refreshTokenValidator, AuthInstance.getRefreshToken);
authRouter.post("/logout", authMiddleware, AuthInstance.logoutUser);


export default authRouter;