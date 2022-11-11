const express = require("express");
const bodyParser = require("body-parser");
const mongoose = require('mongoose');
const path = require('path')
const cors = require('cors')
const jwt = require('jsonwebtoken');
require('dotenv').config()

// Making app
const app = express();
app.use(cors());

// Parsing mddleware
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({
    extended: false
}));

// Connecting to database
mongoose.connect('mongodb+srv://sandbox:12Sandbox34@sandboxhackathon.imxr1sg.mongodb.net/sandbox?retryWrites=true&w=majority', {
    useUnifiedTopology: true,
    useNewUrlParser: true,
});

const cookieParser = require("cookie-parser");
app.use(cookieParser());

const cookieSession = require('cookie-session');
app.use(cookieSession({
    name: 'session',
    keys: [
        'secretValue'
    ],
    cookie: {
        maxAge: 24 * 60 * 60 * 1000 // 24 hours
    }
}));

// Importing users module and setting API endpoint
const users = require("./users.js");
app.use("/api/users", users.routes);