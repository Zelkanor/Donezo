import express, { urlencoded, type Express } from "express";
import helmet from "helmet";
import morgan from "morgan";
import cors from "cors";
import compression from "compression";
import dotenv from "dotenv";
import cookieParser from "cookie-parser";
dotenv.config();


export const createServer = (): Express => {
  const app = express();
    // Disable "X-Powered-By" header (hide tech stack)
    app.disable("x-powered-by");

    app.use(compression());
    app.use(cookieParser());
    // Enable request body parsing
    app.use(urlencoded({ extended: true }));
    app.use(express.json());

    // Logging HTTP requests (skip in testing/production if desired)
    app.use(morgan("dev"));

    // Cross-Origin Resource Sharing
    app.use(
    cors({
      origin: process.env.CLIENT_URL || '*', // replace with frontend domain
      methods: ["GET", "POST", "PUT", "DELETE"],
      allowedHeaders: ["Content-Type", "Authorization"],
      credentials: true,
      })
    );

    app.use(
      helmet({
        frameguard: { action: "deny" }, // X-Frame-Options
        referrerPolicy: { policy: "no-referrer" },
        contentSecurityPolicy: false, // optional if you want to customize CSP separately
      })
    );

  return app;
};


