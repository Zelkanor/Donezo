import { PrismaClient } from '../../generated/prisma/client'

export class PrismaInstance {
  private static instance: PrismaClient | null = null;

  private constructor() {}

  public static getInstance(): PrismaClient {
    if (!this.instance) {
      this.instance = new PrismaClient();
    }
    return this.instance;
  }

}