const express = require("express");
const mongoose = require('mongoose');
const argon2 = require("argon2");
const jwt = require('jsonwebtoken');
const router = express.Router();
const app = express();

// Business schema
const businessSchema = new mongoose.Schema({
    companyName: String,
    username: String,
    password: String,
    email: String,
    businessLink: String,
    city: String,
    state: String,
    country: String,
    isModel: Boolean,
    created: {
        type: Date,
        default: Date.now
    },
});

// Business record
businessSchema.pre('save', async function (next) {
    // Hash si fue modificado o nuevo
    if (!this.isModified('password'))
        return next();

    try {
        const hash = await argon2.hash(this.password);
        // hash sobre escritura
        this.password = hash;
        next();
    } catch (error) {
        console.log(error);
        next(error);
    }
});

// Compare password
businessSchema.methods.comparePassword = async function (password) {
    try {
        const validMatch = await argon2.verify(this.password, password);
        return validMatch;
    } catch (error) {
        return false;
    }
};

// Business to JSON
businessSchema.methods.toJSON = function () {
    var obj = this.toObject();
    delete obj.password;
    return obj;
}

// Creating business object using mongoose schema
const Business = mongoose.model('Business', businessSchema);

/* Middleware */

const validBusiness = async (req, res, next) => {
    if (!req.session.businessID)
        return res.status(403).send({
            message: "not logged in"
        });
    try {
        const business = await Business.findOne({
            _id: req.session.businessID
        });
        if (!business) {
            return res.status(403).send({
                message: "not logged in"
            });
        }
        // pedir al usuario loggeado
        req.business = business;
    } catch (error) {
        // error si usuario no existe
        return res.status(403).send({
            message: "not logged in"
        });
    }

    // ir al siguiente middleware
    next();
};

/* API Endpoints */

// Create business and put into database
router.post('/', async (req, res) => {
    // Not required: || !req.body.city || !req.body.state || !req.body.country || !req.body.businessLink
    // Required information:
    if (!req.body.companyName || !req.body.username || !req.body.password || !req.body.email)
        return res.status(400).send({
            message: "All variables required except for city, state, country, or business link"
        });

    try {

        //  Chequear si usario ya existe
        const existingBusinessUsername = await Business.findOne({
            username: req.body.username
        });
        if (existingBusinessUsername) {
            return res.status(403).send({
                message: "username already exists"
            });
        }

        // crear nuevo usuario y subirlo a la base de datos
        const business = new Business({
            companyName: req.body.companyName,
            username: req.body.username,
            password: req.body.password,
            email: req.body.email,
            businessLink: req.body.businessLink,
            city: req.body.city,
            state: req.body.state,
            country: req.body.country,
            isModel: false,
        });
        await business.save();
        // informacion de la sesion del usuario
        req.session.businessID = business._id;
        const payload = {
            check: true,
            business: business
        };
        const token = jwt.sign(payload, process.env.SECRET_JWT, {
            expiresIn: 1440
        });
        // hacer saber que el usuario fue creado
        return res.status(200).send({
            message: "Business created",
            status: true,
            business: business,
            token: token
        });
    } catch (error) {
        console.log(error);
        return res.sendStatus(500);
    }
});

// logging business
router.post('/login', async (req, res) => {
    // Require username and password
    if (!req.body.username || !req.body.password)
        return res.sendStatus(400);

    try {
        //  Ver el record del usuario
        const business = await Business.findOne({
            username: req.body.username
        });
        // Error si el usuario es malo
        if (!business)
            return res.status(403).send({
                status: false,
                message: "username or password is wrong"
            });

        // Error si el password es malo
        if (!await business.comparePassword(req.body.password))
            return res.status(403).send({
                status: false,
                message: "username or password is wrong"
            });

        const payload = {
            check: true,
            business: business
        };
        const token = jwt.sign(payload, process.env.SECRET_JWT, {
            expiresIn: 1440
        });

        return res.status(200).send({
            status: true,
            business: business,
            token: token
        });

    } catch (error) {
        console.log(error);
        return res.sendStatus(500);
    }
});

// Get the current business
router.get('/:businessID', async (req, res) => {
    try {
        let businessFound = await Business.findOne({ _id: req.params.businessID });
        console.log(businessFound)
        await businessFound.save();
        return res.send(businessFound);
    } catch (error) {
        console.log(error);
        return res.sendStatus(500);
    }
});

// Log out
router.delete("/", validBusiness, async (req, res) => {
    try {
        req.session = null;
        res.sendStatus(200);
    } catch (error) {
        console.log(error);
        return res.sendStatus(500);
    }
});

module.exports = {
    routes: router,
    model: Business,
    valid: validBusiness
};