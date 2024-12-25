import config from "./config.js";

import http from 'http';
import express from "express";
import { Server } from 'socket.io';
// srp

import api from "./api.js";
import { Database } from "./db.js";

export const db = new Database(config);
db.connect();

let app = express();
let server = http.Server(app);
export const io = new Server(server, {
	serveClient: false,
});
app.use(express.json());

app.use("/api/v1/", api);

// ! do NOT put anything after this otherwise they will be bypassed in prod
server.listen(config.port, () => {
	console.log(`Server started on port ${config.port}`);
});