import { Router } from "express";
import { db } from "./index.js";

const router = Router();

router.use((req, res, next) => {
    req.session = db.findSession(req.headers.authorization);
    next();
});

router.get("/ping", (req, res) => {
    res.send("pong");
});

router.get("/session", (req, res) => {
    if (req.session) {
        return res.send(req.session);
    }
    res.status(404).json({error: "session not found"});
});

router.post("/session", (req, res) => { // generate a new login attempt
    if (req.session) {
        return res.status(400).json({error: "session already exists"});
    }
    if (!req.body) {
        res.status(400).json({error: "username or email required"});
    }
    if (!req.username) {
        res.status(400).json({error: "username or email required"});
    }
    if (/^(([^<>()\[\]\\.,;:\s@"]+(\.[^<>()\[\]\\.,;:\s@"]+)*)|(".+"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$/.test(req.username)) { // try to convert username to email
        req.username = db.findUsernameByEmail(req.username);
        if (!req.username) {
            res.status(404).json({error: "username or email not found"});
        }
    }
    const session = db.createLoginAttempt(req.username);
    if (!session) {
        return res.status(500).json({error: "failed to create login attempt"});
    }
    res.send(session);
});

router.patch("/session", (req, res) => { // verify login attempt
    if (!req.session) {
        return res.status(400).json({error: "session not found"});
    }
    if (req.session.loggedIn) {
        return res.status(400).json({error: "session already logged in"});
    }
    if (!req.body || !req.body.clientEphemeral || !req.body.proof) {
        res.status(400).json({error: "client ephemeral and proof required"});
    }
    const serverSession = db.verifyLoginAttempt(req.session.id, req.body.clientEphemeral, req.body.proof, req.body.description || req.headers["user-agent"] || "unknown");
    if (!serverSession) {
        return res.status(401).json({error: "login attempt failed"});
    }
    res.send(serverSession);
});

router.delete("/session", (req, res) => {
    if (!req.session) {
        return res.status(400).json({error: "session not found"});
    }
    db.deleteSession(req.session.id);
    res.send("ok");
});














export default router;