import { Router } from "express";
import { WorkspaceController } from "../controllers/workspaceController";

const workspaceRouter:Router = Router(); 
const workspaceController = WorkspaceController.getInstance();

workspaceRouter.post("/workspace", );
workspaceRouter.get("/workspace", );
workspaceRouter.get("/workspace/:id", );
workspaceRouter.patch("/workspace/:id", );
workspaceRouter.delete("/workspace/:id", );

workspaceRouter.get("/workspace/:id/members", );
workspaceRouter.patch("/workspace/:id/members/:memberId", );
workspaceRouter.delete("/workspace/:id/members/:memberId", );

export default workspaceRouter;