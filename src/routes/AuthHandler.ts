import { compare, hash } from "bcrypt";
import { Router } from "express";
import { sign } from "jsonwebtoken";
import { authoriseValidation, loginValidation, registerValidation } from "../lib/validation";
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
        authorisations: []
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
    if(!(user.admin || user.authorisations.includes('auth-info'))) return res.status(403).send('Access denied!');
    return res.json(UserModel.find());
});

AuthHandler.get('/info/:id', useAuth, async (req: AuthenticatedRequest, res) => {
    const user = req.user!;
    if(!(user.admin || user.authorisations.includes('auth-info'))) return res.status(403).send('Access denied!');
    return res.json(UserModel.find({_id: req.params.id}));
});

AuthHandler.post('/authorise/:id', useAuth, async (req: AuthenticatedRequest, res) => {
    const reqSender = req.user!;
    if(!reqSender.admin) return res.status(403).send('Access denied!');
    const { error } = authoriseValidation(req.body);
    if (error) return res.status(400).send(error.details[0].message);
    const user = await UserModel.findOne({_id: req.params.id});
    if(!user) return res.status(400).send('Account does not exist!');
    if(user.authorisations.includes(req.body.authorisation)) return res.status(400).send('User already authorised!');
    user.authorisations.push(req.body.authorisation);
    user.save();
    return res.status(200).json({authorisation: req.body.authorisation});
})

AuthHandler.post('/deauthorise/:id', useAuth, async (req: AuthenticatedRequest, res) => {
    const reqSender = req.user!;
    if(!reqSender.admin) return res.status(403).send('Access denied!');
    const { error } = authoriseValidation(req.body);
    if (error) return res.status(400).send(error.details[0].message);
    const user = await UserModel.findOne({_id: req.params.id});
    if(!user) return res.status(400).send('Account does not exist!');
    if(!user.authorisations.includes(req.body.authorisation)) return res.status(400).send('User not authorised!');
    user.authorisations = user.authorisations.filter(s => s !== req.body.authorisation);
    user.save();
    return res.status(200).json({authorisation: req.body.authorisation});
})

export { AuthHandler };