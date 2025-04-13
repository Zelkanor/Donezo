
export class UserController {
    public static instance:UserController | null = null;
    private constructor() {}

    public static getInstance(): UserController {
        if (!this.instance) {
            this.instance = new UserController();
        }
        return this.instance;
    }
}