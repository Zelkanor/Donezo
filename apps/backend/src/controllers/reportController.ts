import { PrismaInstance } from '../config/prisma_client';
import {PrismaClient} from '../../generated/prisma/client'

export class ReportController {
    public static instance: ReportController | null = null;
    private prisma: PrismaClient;
    private constructor() {
        this.prisma = PrismaInstance.getInstance();
    }

    public static getInstance(): ReportController {
        if (!this.instance) {
            this.instance = new ReportController();
        }
        return this.instance;
    }
}