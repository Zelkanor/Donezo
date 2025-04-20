import express, { urlencoded, type Express } from "express";
import helmet from "helmet";
import morgan from "morgan";
import cors from "cors";
import compression from "compression";
import dotenv from "dotenv";
import cookieParser from "cookie-parser";
import rateLimit from 'express-rate-limit';
import { Request, Response,NextFunction } from 'express';
dotenv.config();


export const createServer = (): Express => {
  const app = express();
    // Disable "X-Powered-By" header (hide tech stack)
    app.disable("x-powered-by");

    app.use(compression());
    app.use(cookieParser());
    // Enable request body parsing
    app.use(urlencoded({ extended: true }));
    app.use(express.json({limit: '10kb'}));

    // Logging HTTP requests 
    app.use(morgan("dev"));

    // Cross-Origin Resource Sharing
    app.use(
    cors({
      origin: process.env.CLIENT_URL || '*', // replace with frontend domain
      methods: ["GET", "POST", "PUT", "DELETE","PATCH"],
      allowedHeaders: ["Content-Type", "Authorization"],
      credentials: true,
      })
    );

    app.use(
      helmet({
        frameguard: { action: "deny" }, // X-Frame-Options
        referrerPolicy: { policy: "no-referrer" },
        contentSecurityPolicy: {
          directives: {
            defaultSrc: ["'self'"],
            scriptSrc: ["'self'", "'unsafe-inline'"],
            styleSrc: ["'self'", "'unsafe-inline'"],
            imgSrc: ["'self'", "data:"],
            connectSrc: ["'self'", process.env.CLIENT_URL || '']
          }
        },
        hsts:{
          maxAge: 63072000, // 2 years in seconds
          includeSubDomains: true,
          preload: true
        }
      })
    );

    const globalLimiter = rateLimit({
      windowMs: 15 * 60 * 1000, // 15 minutes
      max: 100 // limit each IP to 100 requests per windowMs
    });
    app.use(globalLimiter);
    app.use((err: Error, req: Request, res: Response, next: NextFunction) => {
      console.error(err.stack);
      res.status(500).json({ error: 'Internal Server Error' });
    });

    app.get('/health', (req, res) => {
      res.status(200).json({ status: 'UP' });
    });

  return app;
};


