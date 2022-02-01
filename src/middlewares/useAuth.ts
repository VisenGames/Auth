import { Request, Response, NextFunction } from "express";
import { JwtPayload, verify } from "jsonwebtoken";
import { infoValidation } from "../lib/validation";
import { User, UserModel } from "../models/User";

export type AuthenticatedRequest = Request & {
    user?: User
}

const validateJwt = async (token?: string): Promise<User | null> => {
    let jwt: string | JwtPayload;
    try {
        jwt = verify(token ?? "", process.env.TOKEN_SECRET!);
    } catch {
        return null;
    }

    const { error } = infoValidation(jwt);
    if(error || typeof jwt === "string") return null;

    const user = await UserModel.findOne({ _id: jwt._id });

    return user ?? null;
}

export const useAuth = async (req: AuthenticatedRequest, res: Response, next: NextFunction) => {

    const auth = req.header("authorization");

    if(!auth || !auth.startsWith("Bearer "))
        return res.status(403).send("Access denied");
        
    const token = auth.slice("Bearer ".length);
    const validated = await validateJwt(token);
    if(!validated)
        return res.status(403).send("Access denied");

    req.user = validated;
    next()
}