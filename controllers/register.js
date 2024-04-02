const { User } = require("../models/db");
const bcrypt = require("bcrypt");

const jwt = require("jsonwebtoken");
const logger = require("../logger/index_logger");
require("dotenv").config();

exports.form = (req, res) => {
  res.render("registerForm", { title: "Register" });
};

exports.submit = async (req, res, next) => {
  try {
    const user = await User.findOne({
      where: { email: req.body.dataForm.email },
    });
    if (user) {
      res.error("Такой пользователь в базе есть");
      res.redirect("back");
    } else {
      const SALT = Number(process.env.SALT);
      const salt = await bcrypt.genSalt(SALT);
      const hash = await bcrypt.hash(req.body.dataForm.password, salt);
      await User.create({
        name: req.body.dataForm.name,
        email: req.body.dataForm.email,
        password: hash,
        age: req.body.dataForm.age,
      });

      req.session.userEmail = req.body.dataForm.email;
      req.session.userName = req.body.dataForm.name;
      res.redirect("/");
    }
    // генерация токена
    const jwt_time = process.env.jwtTime;
    const token = jwt.sign(
      { name: req.body.dataForm.email },
      process.env.jwtToken,
      {
        expiresIn: jwt_time,
      }
    );
    //создание cookies для пользователя
    res.cookie("jwt", token, {
      httpOnly: true,
      maxAge: jwt_time,
    });
    logger.info("First token login " + " transferred successfully");
    res.redirect("/");
  } catch (err) {
    return next(err);
  }
};
