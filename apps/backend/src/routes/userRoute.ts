import { Router } from "express";
import { UserController } from "../controllers/userController";
import upload from "../middlewares/auth/uploadMiddleware";
import { authMiddleware } from "../middlewares/auth/authMiddleware";
import { updateUserProfileValidator } from "../middlewares/validators/validator";
const userRouter:Router = Router();

const userInsatance = UserController.getInstance();


userRouter.get("/profile",authMiddleware, userInsatance.getUserProfile);
userRouter.patch("/profile",authMiddleware,updateUserProfileValidator, userInsatance.updateUserProfile);
userRouter.delete("/profile",authMiddleware, userInsatance.deleteUserProfile);


userRouter.post("/upload-image",upload.single("image"),(req,res)=>{
    if(!req.file) {
        return res.status(400).json({ message: "No file uploaded" });
    }
    const imageUrl = `${req.protocol}://${req.get('host')}/uploads/${req.file.filename}`;
    res.status(200).json({ type:"success" ,message: "File uploaded successfully", imageUrl });
});

export default userRouter;