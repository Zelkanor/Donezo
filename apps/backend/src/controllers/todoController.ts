import { PrismaInstance } from '../config/prisma_client';
import {PrismaClient} from '../../generated/prisma/client'

export class TodoController {
    public static instance: TodoController | null = null;
    private prisma: PrismaClient;
    private constructor() {
        this.prisma = PrismaInstance.getInstance();
    }

    public static getInstance(): TodoController {
        if (!this.instance) {
            this.instance = new TodoController();
        }
        return this.instance;
    }
}