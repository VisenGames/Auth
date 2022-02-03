import Joi from "joi";

export const registerValidation = (data: unknown) => {    
    const schema = Joi.object({
        name: Joi.string().min(6).max(20).required(),
        email: Joi.string().min(6).required().email(),
        password: Joi.string().min(6).max(1024).required(),
    });
    return schema.validate(data);
}

export const loginValidation = (data: unknown) => {    
    const schema = Joi.object({
        email: Joi.string().min(6).required().email(),
        password: Joi.string().min(6).max(1024).required(),
    });
    return schema.validate(data);
}

export const infoValidation = (data: unknown) => {    
    const schema = Joi.object({
        _id: Joi.string().required()
    }).unknown(true);
    return schema.validate(data);
}

export const authoriseValidation = (data: unknown) => {    
    const schema = Joi.object({
        authorisation: Joi.string().required()
    }).unknown(true);
    return schema.validate(data);
}