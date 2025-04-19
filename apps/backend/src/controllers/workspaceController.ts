import { PrismaInstance } from '../config/prisma_client';
import {PrismaClient} from '../../generated/prisma/client'

export class WorkspaceController {
    public static instance: WorkspaceController | null = null;
    private prisma: PrismaClient;
    private constructor() {
        this.prisma = PrismaInstance.getInstance();
    }

    public static getInstance(): WorkspaceController {
        if (!this.instance) {
            this.instance = new WorkspaceController();
        }
        return this.instance;
    }
}