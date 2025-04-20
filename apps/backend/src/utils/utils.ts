import { type SafeParseReturnType } from "zod";
import { JwtPayload } from "../config/types/api_response.interface";
import jwt from 'jsonwebtoken';
import { Resend } from 'resend';
import { mailOptions } from "../config/types/email_type";
import { EmailSendError } from "../errors/error";


export const errorDetails = (data:SafeParseReturnType<any,any>) => {
    const messages = data.error!.errors.map(e => ({
                field: e.path.join("."),
                message: e.message,
              }));
    return messages;
}

//Generate JWT Access token
export const generateAccessToken = (payload:JwtPayload,emergencyToken?:boolean ) => {
  if (emergencyToken) {
    return jwt.sign(payload, process.env.JWT_ACCESS_SECRET as string, {
      expiresIn: '10m',
    });
  }
  return jwt.sign(payload, process.env.JWT_ACCESS_SECRET as string, {
    expiresIn:'15m',
  });
};


//Generate JWT Refresh token
export const generateRefreshToken = (payload:JwtPayload) => {
  return jwt.sign(payload, process.env.JWT_REFRESH_SECRET as string, {
    expiresIn: '7d',
  });
};

export function verifyToken(token:string,type:"access"|"refresh"):JwtPayload {
  if (type === "refresh") {
    return jwt.verify(token, process.env.JWT_REFRESH_SECRET as string) as JwtPayload;
  }
  return jwt.verify(token, process.env.JWT_ACCESS_SECRET as string) as JwtPayload;
}

export function generatePasswordResetToken(userId: string) {
  return jwt.sign({ id: userId }, process.env.JWT_PASSWORD_RESET_SECRET!, { expiresIn: '15m' });
}

export function verifyPasswordResetToken(token: string): { id: string } {
  console.log("verifying password reset token", token);
  return jwt.verify(token, process.env.JWT_PASSWORD_RESET_SECRET!) as { id: string };
}

export async function sendMail(mailOptions: mailOptions) {
  const resend = new Resend(process.env.RESEND_API_KEY!);
  const resp = await resend.emails.send({
    from: mailOptions.from,
    to: mailOptions.to,
    subject: mailOptions.subject,
    html: mailOptions.html,
  });
  if (resp.error !== null) {
    console.log("Error sending email:", resp);
    throw new EmailSendError("Email send error");
  };

}