import { Router } from "express";
import { UserController } from "../controllers/userController";
import upload from "../middlewares/auth/middlewares/uploadMiddleware";
const userRoute:Router = Router();


const userController = UserController.getInstance();
userRoute.post("/upload-image",upload.single("image"),(req,res)=>{
    if(!req.file) {
        return res.status(400).json({ message: "No file uploaded" });
    }
    const imageUrl = `${req.protocol}://${req.get('host')}/uploads/${req.file.filename}`;
    res.status(200).json({ type:"success" ,message: "File uploaded successfully", imageUrl });
});

export default userRoute;