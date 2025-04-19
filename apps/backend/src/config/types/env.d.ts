declare namespace NodeJS{
    export interface ProcessEnv{
        PORT:string;
        JWT_ACCESS_SECRET:string;
        JWT_REFRESH_SECRET:string;
    }
}