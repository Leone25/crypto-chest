import config from "./config.js";

import yargs from "yargs";
import http from 'http';
import express from "express";
import { Server } from 'socket.io';

export const argv = yargs(process.argv)
	.option("prod", {
		alias: "p",
		description: "Run in production mode",
		type: "boolean",
		default: false,
	})
	.help()
	.alias("help", "h").argv;

import api from "./api.js";
import Database from "./database.js";

export const db = new Database(config);

let app = express();
let server = http.Server(app);
export const io = new Server(server, {
	serveClient: false,
});
app.use(express.json());

app.use("/api/v1/", api);

if (argv.prod) {
	app.use("/", express.static("../client/dist"));
	app.use((req, res) => {
		res.sendFile("../client/dist/index.html");
	});
}
// ! do NOT put anything after this otherwise they will be bypassed in prod
server.listen(config.port, () => {
	console.log(`Server started on port ${config.port}`);
});