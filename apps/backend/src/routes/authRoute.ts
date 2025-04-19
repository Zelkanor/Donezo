import { Router } from "express";
import { AuthController } from "../controllers/authController";
import { authMiddleware } from "../middlewares/auth/authMiddleware";
import { forgotPasswordValidator, loginUserValidator, refreshTokenValidator, registerUserValidator, resetPasswordValidator } from "../middlewares/validators/validator";
const authRouter:Router = Router();

const AuthInstance = AuthController.getInstance();

authRouter.post("/register",registerUserValidator,AuthInstance.registerUser);
authRouter.post("/login",loginUserValidator, AuthInstance.loginUser);
authRouter.post("/forgot-password",forgotPasswordValidator, AuthInstance.forgotPassword);
authRouter.post("/reset-password",resetPasswordValidator, AuthInstance.resetPassword);
authRouter.post("/refresh-token",refreshTokenValidator, AuthInstance.getRefreshToken);
authRouter.post("/logout", authMiddleware, AuthInstance.logoutUser);


export default authRouter;