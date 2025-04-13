import { z } from 'zod';

export const SignUpSchema = z.object({
    firstName: z.string().trim().min(3, { message: 'First name is required' }).max(50, { message: 'First name must be less than 50 characters' }),
    lastName: z.string().trim().min(3).max(50, { message: 'Last name must be less than 50 characters' }).optional(),
    userName: z.string().trim().min(3, { message: 'Username is required' }).max(50, { message: 'Username must be less than 50 characters' }).regex(/^[a-zA-Z0-9_.]+$/, { message: 'Username can only contain letters, numbers, underscores, and periods' }),
    countryCode: z.string().trim().regex(/^\+\d{1,4}$/, {message: "Country code must be in the format +123",}).optional(),
    phoneNumber: z.string().trim().regex(/^[0-9]{6,15}$/, { message: 'Phone number must be 6 to 15 digits long' }).optional(),
    email: z.string().trim().email({ message: 'Invalid email address' }),
    password: z.string().trim().min(8, "Password must be at least 8 characters long").max(25,"Password cannot be more than 25 characters").regex(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/,{message:"Password must include at least one uppercase letter, one lowercase letter, one number, and one special character",}),
    profileImageUrl: z.string().trim().url({ message: 'Invalid URL' }).optional(),
})

export const LoginSchema = z.object({
    email: z.string().trim().email({ message: 'Invalid email address' }),
    password: z.string().trim().min(8, "Password must be at least 8 characters long").max(25,"Password cannot be more than 25 characters").regex(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/,{message:"Password must include at least one uppercase letter, one lowercase letter, one number, and one special character",}),
});

export const UpdateUserProfileSchema = z.object({
    userName: z.string().trim().min(3, { message: 'Username is required' }).max(50, { message: 'Username must be less than 50 characters' }).regex(/^[a-zA-Z0-9_.]+$/, { message: 'Username can only contain letters, numbers, underscores, and periods' }).optional(),
    countryCode: z.string().trim().regex(/^\+\d{1,4}$/, {message: "Country code must be in the format +123",}).optional(),
    phoneNumber: z.string().trim().regex(/^[0-9]{6,15}$/, { message: 'Phone number must be 6 to 15 digits long' }).optional(),
});

export const forgotPasswordSchema = LoginSchema.pick({password: true})


export type SignUpResponse = {
    id: string,
    accessToken: string,
    refreshToken: string,
}

export type LoginResponse = SignUpResponse


export type JWTPayload = {
    id: string,
    sessionId: string,
    iat: number,
}

export type SignUpType = z.infer<typeof SignUpSchema>;
export type LoginType = z.infer<typeof LoginSchema>;

export type UpdateUserProfileType = z.infer<typeof UpdateUserProfileSchema>;
export type ForgotPasswordType = z.infer<typeof forgotPasswordSchema>;