import { Router } from "express";
import { ReportController } from "../controllers/reportController";


const reportRouter:Router = Router(); 
const repoteController = ReportController.getInstance();

reportRouter.post("/export/tasks/", );         
reportRouter.get("/export/users", );          


export default reportRouter;