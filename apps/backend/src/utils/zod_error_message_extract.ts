import { type SafeParseReturnType } from "zod";

export const errorDetails = (data:SafeParseReturnType<any,any>) => {
    const messages = data.error!.errors.map(e => ({
                field: e.path.join("."),
                message: e.message,
              }));
    return messages;
}