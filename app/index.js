import express from 'express';
import pg from 'pg';
import NodeRSA from 'node-rsa';
import Vault from "hashi-vault-js";

const { Pool } = pg;
const pool = new Pool({
    user: 'root',
    password: 'mySecretPassword',
    host: 'postgres',
    port: 5432,
    database: 'test'
});

const vault = new Vault({
    https: false,
    baseUrl: 'http://vault:8201/v1',
    rootPath: 'secret',
    timeout: 5000,
    proxy: false
});


const app = new express();

app.use(express.json());

app.get("/ping", (req, res) => {
    return res.status(200).json("pong");
});

app.get("/secret/token", async (req, res) => {
    const token = await vault.readKVSecret("mySecretPassword", req.username);
    return res.status(200).json({token: token});
});

app.post("/secret/token", async (req, res) => {
    const user = req.body.username;
    const token = req.body.token;

    await vault.createKVSecret("mySecretPassword", user, token);
    return res.status(200);
});

app.get("/secret/public_key", (req, res) => {
    const key = new NodeRSA();
    key.setOptions({environment: 'node'});
    key.generateKeyPair(2048, 65537);
    return res.status(200).json({public_key: key.exportKey('pkcs8-public-pem'), private_key: key.exportKey('pkcs8-private-pem')});
});

app.get("secret/data", async (req, res) => {
    const query = 'SELECT * FROM encrypted_data;'
    const result = await pool.query(query);
    return res.status(200).json({data: result.rows});
})

app.post("/secret/data", async (req, res) => {
    console.log(req.body.canvasData);
    const data = req.body.canvasData;
    const keyData = req.body.public_key;
    const key = new NodeRSA();
    key.setOptions({environment: 'node'});
    key.importKey(keyData, 'pkcs8-public-pem');
    const encryptedData = key.encrypt(data, 'base64', 'utf-8');
    console.log(encryptedData.toString())
    const query = 'INSERT INTO encrypted_data(data) VALUES($1);'
    const values=[encryptedData.toString()]
    await pool.query(query, values)
    return res.status(200).json()
});

app.listen(3000, () => {
    console.log("Listening on http://localhost:3000")
})
