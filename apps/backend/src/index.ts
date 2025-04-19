import { createServer } from "./server";
import authRouter from "./routes/authRoute";
import userRouter from "./routes/userRoute";
import workspaceRouter from "./routes/workspaceRoute";
import todoRouter from "./routes/todoRoute";

const port = process.env.PORT || 5001;
const server = createServer();

server.use("/api/v1/auth",authRouter);
server.use("/api/v1/user",userRouter);
server.use("/api/v1/workspace",workspaceRouter);
server.use("/api/v1/workspace",todoRouter);

server.listen(port, () => {
  console.log(`Server running on ${port}`);
});
