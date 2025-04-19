import multer, { FileFilterCallback } from "multer";

//Configure Storage
const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        cb(null, "uploads/");
    },
    filename: (req, file, cb) => {
        cb(null,`${Date.now()}-${file.originalname}`);
    }
});

//File Filter
const fileFilter = (req:any,file:Express.Multer.File,cb:FileFilterCallback) => {
    const allowedTypes = ["image/jpeg", "image/png", "image/jpg"];
    if(allowedTypes.includes(file.mimetype)){
        cb(null, true);
    } else {
        cb(new Error("Only .jpeg .jpg and .png files are allowed"));
    }
};


const upload = multer({storage,fileFilter});

export default upload;