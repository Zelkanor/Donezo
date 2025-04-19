import { Router } from "express";
import { TodoController } from "../controllers/todoController";

const todoRouter:Router = Router(); 
const todoController = TodoController.getInstance();

todoRouter.post("/workspace/tasks/:taskId/todos", );         // Create a todo
todoRouter.get("/workspace/tasks/:taskId/todos", );          // Get all todos in a task
todoRouter.patch("/workspace/tasks/:taskId/todos/:todoId", );// Update text or completion
todoRouter.delete("/workspace/tasks/:taskId/todos/:todoId", ); // Delete a todo





export default todoRouter;