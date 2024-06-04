const express = require("express");
const router = new express.Router();
const User = require("../models/user");
const { createToken } = require("../helpers/tokens");

/** POST /login - login: {username, password} => {token} **/
router.post("/login", async function (req, res, next) {
    try {
        const { username, password } = req.body;

        if (!username || !password) {
            const err = new Error("Username and password are required");
            err.status = 400;
            throw err;
        }

        const isAuthenticated = await User.authenticate(username, password);
        if (isAuthenticated) {
            await User.updateLoginTimestamp(username);
            const token = createToken(username);
            return res.json({ token });
        } else {
            throw new Error("Invalid username/password");
            err.status = 401;
            throw err;
        }
    } catch (err) {
        return next(err);
    }
});

/** POST /register - register user: registers, logs in, and returns token.
 *
 * {username, password, first_name, last_name, phone} => {token}.
 *
 *  Make sure to update their last-login!
 */
router.post("/register", async function (req, res, next) {
    try {
        const { username, password, first_name, last_name, phone } = req.body;
        if (!username || !password || !first_name || !last_name || !phone) {
            const err = new Error("All fields are required");
            err.status = 400;
            throw err;
        }

        const newUser = await User.register(req.body);
        await User.updateLoginTimestamp(newUser.username);
        const token = createToken(newUser.username);
        return res.json({ token });
    } catch (err) {
        if (err.code === '23505') {
            const duplicateErr = new Error("Username already taken");
            duplicateErr.status = 400;
            return next(duplicateErr);
        }
        return next(err);
    }
});

module.exports = router;
