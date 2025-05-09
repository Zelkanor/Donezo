import { PrismaInstance } from '../config/prisma_client';
import {PrismaClient} from '../../generated/prisma/client'

export class TaskController {
    public static instance: TaskController | null = null;
    private prisma: PrismaClient;
    private constructor() {
        this.prisma = PrismaInstance.getInstance();
    }

    public static getInstance(): TaskController {
        if (!this.instance) {
            this.instance = new TaskController();
        }
        return this.instance;
    }
}