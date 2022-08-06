import express from 'express';
import cors from 'cors';
import router from './src/routes/index.js';
import "./src/clients/db.js";
import dotenv from "dotenv";
dotenv.config();

const app = express(); // create express app


app.use(cors()); // enable cors 


app.use(express.json()); // parse JSON bodies (as sent by API clients)
app.use(express.urlencoded({ extended: true })); // parse URL-encoded bodies (as sent by API clients)

app.use(router); // use router for all requests




app.listen(process.env.PORT || 5000, () => {console.log('Server started on port 5000')});

