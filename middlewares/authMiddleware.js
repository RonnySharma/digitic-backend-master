const User = require('../models/userModel');
const jwt = require('jsonwebtoken');
const asyncHandler = require("express-async-handler");

const authMiddleware = asyncHandler(async (req, res, next) => {
    let token;

    if (req.headers.authorization && req.headers.authorization.startsWith("Bearer")) {
        token = req.headers.authorization.split(" ")[1];

        try {
            const decoded = jwt.verify(token, process.env.JWT_SECRET);
            const user = await User.findById(decoded.id);

            if (!user) {
                return next(new Error("User not found"));
            }

            req.user = user;
            next();
        } catch (error) {
            if (error.name === 'TokenExpiredError') {
                return next(new Error("Token expired"));
            }
            return next(new Error("Not authorized"));
        }
    } else {
        return next(new Error("No token provided"));
    }
});

const isAdmin = asyncHandler(async (req, res, next) => {
    try {
        const { email } = req.user;
        const adminUser = await User.findOne({ email });

        if (!adminUser || adminUser.role !== 'admin') {
            return next(new Error('Not authorized as an admin'));
        }

        next();
    } catch (error) {
        next(error);
    }
});

module.exports = { authMiddleware, isAdmin };
