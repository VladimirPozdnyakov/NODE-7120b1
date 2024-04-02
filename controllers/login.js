const { User } = require("../models/db");
const jwt = require("jsonwebtoken");
const logger = require("../logger/index_logger");
const bcrypt = require("bcrypt");
require("dotenv").config();

exports.form = (req, res) => {
  res.render("loginForm", { title: "Login" });
  logger.error("Зашли");
};

async function authentificate(dataForm, cb) {
  try {
    const user = await User.findOne({ where: { email: dataForm.email } });
    if (!user) return cb();
    const result = await bcrypt.compare(dataForm.password, user.password);
    if (result) return cb(null, user);
    return cb();
  } catch (err) {
    return cb(err);
  }
}

exports.submit = async (req, res, next) => {
  try {
    const user = await User.findOne({
      where: { email: req.body.loginForm.email },
    });
    if (!user) {
      logger.info("Пользователь не найден");
      return res.redirect("back");
    }
    const result = await bcrypt.compare(
      req.body.loginForm.password,
      user.password
    );

    // генерация токена
    const jwt_time = process.env.jwtTime;
    const token = jwt.sign({ name: data.email }, process.env.jwtToken, {
      expiresIn: jwt_time,
    });
    res.cookie("jwt", token, {
      httpOnly: true,
      maxAge: jwt_time,
    });

    logger.info("");

    res.redirect("/");
    logger.info("Token login " + " transferred successfully");
  } catch (err) {
    next(err);
  }
};

exports.logout = function (req, res, next) {
  res.clearCookie("jwt");
  res.clearCookie("connect.sid");

  req.session.destroy((err) => {
    if (err) return next(err);
    res.redirect("/");
  });
};
