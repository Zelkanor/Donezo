import { Router } from "express";
import { AuthController } from "../controllers/authController";
import { authMiddleware } from "../middlewares/auth/middlewares/authMiddleware";
import { forgotPasswordValidator, loginUserValidator, registerUserValidator, updateUserProfileValidator } from "../middlewares/auth/validator";
const authRouter:Router = Router();

const AuthInstance = AuthController.getInstance();

authRouter.post("/register",registerUserValidator,AuthInstance.registerUser);
authRouter.post("/login",loginUserValidator, AuthInstance.loginUser);
authRouter.get("/profile",authMiddleware, AuthInstance.getUserProfile);
authRouter.put("/profile",authMiddleware,updateUserProfileValidator, AuthInstance.updateUserProfile);
authRouter.post("/forgot-password",authMiddleware,forgotPasswordValidator, AuthInstance.forgotPassword);
authRouter.post("/refresh-token", AuthInstance.getRefreshToken);
authRouter.delete("/profile",authMiddleware, AuthInstance.deleteUserProfile);

export default authRouter;