import { compare, hash } from "bcrypt";
import { genSalt } from "bcrypt";
import { Router } from "express";
import Joi from "joi";
import { sign } from "jsonwebtoken";
import { loginValidation, registerValidation } from "../lib/validation";
import { useAuth, AuthenticatedRequest } from "../middlewares/useAuth";
import { UserModel } from "../models/User";

const AuthHandler = Router();

AuthHandler.post("/register", async (req, res) => {
    const { error } = registerValidation(req.body);

    if(error) return res.status(400).send(error.details[0].message);

    const emailExists = await UserModel.findOne({email: req.body.email});
    if(emailExists) return res.status(400).send('Email already exists!');

    const hashPassword = await hash(req.body.password, 10);

    const user = new UserModel({
        name: req.body.name,
        email: req.body.email,
        password: hashPassword,
    });

    user.save().then((savedUser) => {
        res.status(200).send(savedUser);
    }).catch((err) => {
        res.status(400).send(err);
    });
});

AuthHandler.post("/login", async (req, res) => {
    const { error } = loginValidation(req.body);
    if (error) return res.status(400).send(error.details[0].message);

    const user = await UserModel.findOne({email: req.body.email});
    if(!user) return res.status(400).send('Account does not exist!');

    const validPass = await compare(req.body.password, user.password);

    if(!validPass) return res.status(400).send('Invlid password!');
    
    // Create and assign a token
    const token = sign({_id: user._id}, process.env.TOKEN_SECRET!);

    res.send(token);
});

AuthHandler.get("/info", useAuth, async (req: AuthenticatedRequest, res) => {
    const user = req.user!;

    res.send(user);
})

AuthHandler.get('/all', useAuth, async (req: AuthenticatedRequest, res) => {
    const user = req.user!;
    if(!user.admin) return res.status(403).send('Access denied!');
    return res.json(UserModel.find());
});

AuthHandler.get('/info/:id', useAuth, async (req: AuthenticatedRequest, res) => {
    const user = req.user!;
    if(!user.admin) return res.status(403).send('Access denied!');
    return res.json(UserModel.find({_id: req.params.id}));
});

export { AuthHandler };