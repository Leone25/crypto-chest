import postgres from 'postgres';
import srp from 'secure-remote-password/server.js';

export default class Database {
    constructor(config) {
        this.db = postgres(config.db);
    }

    async findSession(token) {
		if (token == null) return;

        const query = await this.db`SELECT * FROM sessions WHERE id = ${token}`;

        if (query.length === 0) { // maybe it's still a login session
            const query = await this.db`SELECT * FROM "loginAttempts" WHERE id = ${token}`;

            if (query.length === 0) {
                return null;
            }

            return {...query[0], loggedIn: false};
        }

        return {...query[0], loggedIn: true};
    }
    
    async createLoginAttempt(username) {
        const userInfo = await this.getUser(username);

		if (!userInfo) {
			return null;
		}

        const {id, salt, verifier} = userInfo;

        const serverEphemeral = srp.generateEphemeral(verifier);

        let loginAttemptId = null;

        for (let i = 0; i < 10; i++) { // let's limit the number of attempts to generate a unique id to avoid infinite loops
            loginAttemptId = Math.random().toString(36).substring(2, 15) + Math.random().toString(36).substring(2, 15);

		console.log(loginAttemptId);

            await this.db`INSERT INTO "loginAttempts" (id, user_id, server_secret, expires) VALUES (${loginAttemptId}, ${id}, ${serverEphemeral.secret}, ${Date.now() + 1000 * 60 * 15})`.catch((err) => {
				console.log(err);
                loginAttemptId = null;
            });

            if (loginAttemptId) {
                break;
            }
        }

        if (!loginAttemptId) { 
            return null;
        }

        return {sessionId: loginAttemptId, username: id, salt, serverEphemeral: serverEphemeral.public};
    }

    async verifyLoginAttempt(id, clientEphemeral, clientProof, description) {
        const query = await this.db`SELECT * FROM "loginAttempts" WHERE id = ${id}`;

        if (query.length === 0) {
            return null;
        }

        const {user_id: username, server_secret: serverEphemeral, expires} = query[0];

		let userInfo = await this.getUser(username);
		console.log(username, userInfo);

        if (expires < Date.now()) {
            await this.db`DELETE FROM "loginAttempts" WHERE id = ${id}`;
            return null;
        }

        let serverSession = null;
        try {
			console.log(serverEphemeral, clientEphemeral, userInfo.salt, username, clientProof);
            serverSession = srp.deriveSession(serverEphemeral, clientEphemeral, userInfo.salt, username, userInfo.verifier, clientProof);
        } catch(err) {
			console.log(err);
            return null;
        }

        // upgrade to session
        await this.db`DELETE FROM "loginAttempts" WHERE id = ${id}`;
        await this.db`INSERT INTO sessions (id, user_id, encryption_key, description, expires) VALUES (${id}, ${username}, ${serverSession.key}, ${description}, ${Date.now() + 1000 * 60 * 60 * 24 * 365})`;

        return {sessionId: id, username, proof: serverSession.proof};
    }

    async deleteSession(token) {
        await this.db`DELETE FROM loginAttempts WHERE id = ${token}`;
        await this.db`DELETE FROM sessions WHERE id = ${token}`;
    }



    async findUsernameByEmail(email) {
        const query = await this.db`SELECT id FROM users WHERE email = ${email}`;

        if (query.length === 0) {
            return null;
        }

        return query[0].id;
    }

	async getUser(username) {
		const query = await this.db`SELECT * FROM users WHERE id = ${username}`;

		if (query.length === 0) {
			return null;
		}

		return query[0];
	}

	async registerUser(username, email, salt, verifier) {
        await this.db`INSERT INTO users (id, email, salt, verifier) VALUES (${username}, ${email}, ${salt}, ${verifier})`;
		return true;
	}
}