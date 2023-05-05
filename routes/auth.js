const express = require("express");
const router = new express.Router();
const jwt = require("jsonwebtoken");
const { SECRET_KEY } = require("../config");
const ExpressError = require("../expressError");
const User = require("../models/user");

/** POST /login - login: {username, password} => {token}
 *
 * Make sure to update their last-login!
 *
 **/
router.post("/login", async (req, res, next) => {
  try {
    let { username, password } = req.body;
    if (await User.authenticate(username, password)) {
      const token = jwt.sign({ username }, SECRET_KEY);
      await User.updateLoginTimestamp(username);
      return res.json({ token });
    }
    throw new ExpressError("Invalid username or password", 400);
  } catch (e) {
    return next(e);
  }
});

/** POST /register - register user: registers, logs in, and returns token.
 *
 * {username, password, first_name, last_name, phone} => {token}.
 *
 *  Make sure to update their last-login!
 */
router.post("/register", async (req, res, next) => {
  try {
    const { username } = await User.register(req.body);
    const token = jwt.sign({ username }, SECRET_KEY);
    return res.json({ token });
  } catch (e) {
    return next(e);
  }
});

module.exports = router;
