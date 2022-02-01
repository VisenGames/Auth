import { model, Schema } from "mongoose";

export type User = {
    name: string,
    email: string,
    password: string,
    date: Date,
    admin: boolean
}

const userSchema = new Schema<User>({
    name: {
        type: String,
        required: true,
        min: 6,
        max: 20
    },
    email: {
        type: String,
        required: true,
        max: 255
    },
    password: {
        type: String,
        required: true,
        max: 1024,
        min: 6
    },
    date: {
        type: Date,
        default: Date.now
    },
    admin: {
        type: Boolean,
        default: false
    }
    
});

export const UserModel = model('User', userSchema);