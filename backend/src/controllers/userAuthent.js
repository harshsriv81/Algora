const redisClient = require("../config/redis");
const User = require("../models/user")
const validate = require('../utils/validator');
const bcrypt = require("bcrypt");
const jwt = require('jsonwebtoken');
const Submission = require("../models/submission")

const cookieOptions = {
    maxAge: 7 * 24 * 60 * 60 * 1000,
    httpOnly: true,
    secure: true,
    sameSite: 'none'
};

const register = async (req, res) => {
    try {
        validate(req.body);
        const { firstName, emailId, password } = req.body;

        req.body.password = await bcrypt.hash(password, 10);
        req.body.role = 'user';

        const user = await User.create(req.body);
        const token = jwt.sign(
            { _id: user._id, emailId: emailId, role: 'user' },
            process.env.JWT_KEY,
            { expiresIn: '7d' }
        );

        const reply = {
            firstName: user.firstName,
            emailId: user.emailId,
            _id: user._id,
            role: user.role,
        }

        res.cookie('token', token, cookieOptions);
        res.status(201).json({
            user: reply,
            token: token, // ✅ send token in response body
            message: "Registered Successfully"
        })
    }
    catch (err) {
        res.status(400).send("Error: " + err);
    }
}

const login = async (req, res) => {
    try {
        const { emailId, password } = req.body;

        if (!emailId) throw new Error("Invalid Credentials");
        if (!password) throw new Error("Invalid Credentials");

        const user = await User.findOne({ emailId });
        if (!user) throw new Error("Invalid Credentials");

        const match = await bcrypt.compare(password, user.password);
        if (!match) throw new Error("Invalid Credentials");

        const reply = {
            firstName: user.firstName,
            emailId: user.emailId,
            _id: user._id,
            role: user.role,
        }

        const token = jwt.sign(
            { _id: user._id, emailId: emailId, role: user.role },
            process.env.JWT_KEY,
            { expiresIn: '7d' }
        );

        res.cookie('token', token, cookieOptions);
        res.status(201).json({
            user: reply,
            token: token, // ✅ send token in response body
            message: "Login Successfully"
        })
    }
    catch (err) {
        res.status(401).send("Error: " + err);
    }
}

const logout = async (req, res) => {
    try {
        let token = req.cookies?.token;

        // ✅ also check Authorization header
        if (!token && req.headers.authorization) {
            token = req.headers.authorization.split(' ')[1];
        }

        if (!token) throw new Error("Token not present");

        const payload = jwt.decode(token);

        await redisClient.set(`token:${token}`, 'Blocked');
        await redisClient.expireAt(`token:${token}`, payload.exp);

        res.cookie("token", null, {
            expires: new Date(Date.now()),
            httpOnly: true,
            secure: true,
            sameSite: 'none'
        });
        res.send("Logged Out Successfully");
    }
    catch (err) {
        res.status(503).send("Error: " + err);
    }
}

const adminRegister = async (req, res) => {
    try {
        validate(req.body);
        const { firstName, emailId, password } = req.body;

        req.body.password = await bcrypt.hash(password, 10);

        const user = await User.create(req.body);
        const token = jwt.sign(
            { _id: user._id, emailId: emailId, role: user.role },
            process.env.JWT_KEY,
            { expiresIn: '7d' }
        );

        res.cookie('token', token, cookieOptions);
        res.status(201).json({
            token: token, // ✅ send token in response body
            message: "Admin Registered Successfully"
        });
    }
    catch (err) {
        res.status(400).send("Error: " + err);
    }
}

const deleteProfile = async (req, res) => {
    try {
        const userId = req.result._id;
        await User.findByIdAndDelete(userId);
        res.status(200).send("Deleted Successfully");
    }
    catch (err) {
        res.status(500).send("Internal Server Error");
    }
}

module.exports = { register, login, logout, adminRegister, deleteProfile };