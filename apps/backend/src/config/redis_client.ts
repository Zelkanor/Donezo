import Redis from "ioredis";

export class RedisClient {
    private static instance: Redis;
    private constructor() {};

    public static getInstance(): Redis {
        if (!this.instance) {
            this.instance = new Redis(
                process.env.REDIS_URL || "redis://localhost:6379",
            );
            this.instance.on("error", (err) => {
                console.error("Redis Client Error", err);
            });
            this.instance.on("connect", () => {
                console.log("Redis Client Connected");
            });
        }
        return this.instance;
    }
}
