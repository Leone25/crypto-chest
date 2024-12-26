import { Router } from "express";
import { db } from "./index.js";

const router = Router();

router.use(async (req, res, next) => {
    req.session = await db.findSession(req.headers.authorization);
	//console.log(req.session);
    next();
});

router.get("/ping", (req, res) => {
    res.send("pong");
});

router.post("/users", async (req, res) => { // register a new user
	if (!req.body || !req.body.username || !req.body.email || !req.body.salt || !req.body.verifier) {
		return res.status(400).json({error: "Missing username, email salt or verifier"});
	}
	if (await db.registerUser(req.body.username, req.body.email, req.body.salt, req.body.verifier)) {
		return res.send("ok");
	}
	return res.status(400).json({error: "Error registering"});
});

router.get("/session", (req, res) => {
    if (req.session) {
        return res.send(req.session);
    }
    res.status(404).json({error: "session not found"});
});

router.post("/session", async (req, res) => { // generate a new login attempt
    if (req.session) {
        return res.status(400).json({error: "session already exists"});
    }
    if (!req.body) {
        return res.status(400).json({error: "username or email required"});
    }
    if (!req.body.username) {
        return res.status(400).json({error: "username or email required"});
    }
    if (/^(([^<>()\[\]\\.,;:\s@"]+(\.[^<>()\[\]\\.,;:\s@"]+)*)|(".+"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$/.test(req.body.username)) { // try to convert username to email
        req.body.username = await db.findUsernameByEmail(req.body.username);
        if (!req.body.username) {
            res.status(404).json({error: "username or email not found"});
        }
    } else if (!await db.getUser(req.body.username)) {
		return res.status(404).json({error: "username or email not found"});
	}
    const session = await db.createLoginAttempt(req.body.username);
    if (!session) {
        return res.status(500).json({error: "failed to create login attempt"});
    }
    res.send(session);
});

router.patch("/session", async (req, res) => { // verify login attempt
    if (!req.session) {
        return res.status(400).json({error: "session not found"});
    }
    if (req.session.loggedIn) {
        return res.status(400).json({error: "session already logged in"});
    }
    if (!req.body || !req.body.clientEphemeral || !req.body.proof) {
        res.status(400).json({error: "client ephemeral and proof required"});
    }
    const serverSession = await db.verifyLoginAttempt(req.session.id, req.body.clientEphemeral, req.body.proof, req.body.description || req.headers["user-agent"] || "unknown");
    if (!serverSession) {
        return res.status(401).json({error: "login attempt failed"});
    }
    res.json(serverSession);
});

router.delete("/session", (req, res) => {
    if (!req.session) {
        return res.status(400).json({error: "session not found"});
    }
    db.deleteSession(req.session.id);
    res.send("ok");
});














export default router;