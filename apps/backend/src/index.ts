import { createServer } from "./server";
import authRouter from "./routes/authRoute";

const port = process.env.PORT || 5001;
const server = createServer();

server.use("/api/v1/auth",authRouter);

server.listen(port, () => {
  console.log(`Server running on ${port}`);
});
