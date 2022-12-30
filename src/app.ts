import Express, { json } from "express";
import { config as dotenvConfig } from "dotenv";
import { connect } from "mongoose";
import { AuthHandler } from "./routes/AuthHandler";
dotenvConfig();

const app = Express();

connect(process.env.DB_CONNECT!, () => {
    console.log("Connected to db");
});

app.use((req, res, next) => {
    console.log(`${req.method} on ${req.path} from ${req.ip}`);
    next();
});

app.use(json());

app.get("/", (req, res) => {
    res.send({ status: 200 });
});

app.use("/api/auth/", AuthHandler);

const _PORT = process.env.PORT || 8080;

app.listen(_PORT, () => {
    console.log("Listening on", _PORT);
});
