import { Router } from "express";
import { TaskController } from "../controllers/taskController";

const taskRouter:Router = Router(); 
const taskController = TaskController.getInstance();

taskRouter.use('/:workspaceId', );
taskRouter.post("/tasks", );
taskRouter.get("/tasks", );
taskRouter.get("/tasks/:id", );
taskRouter.patch("tasks/:id", );
taskRouter.delete("tasks/:id", );

taskRouter.patch("tasks/:id/status", );
taskRouter.patch("tasks/:id/progress", );
taskRouter.patch("tasks/:id/assignee", );
taskRouter.post("tasks/:id/attachments", );
taskRouter.get("tasks/:id/attachments", );



export default taskRouter;