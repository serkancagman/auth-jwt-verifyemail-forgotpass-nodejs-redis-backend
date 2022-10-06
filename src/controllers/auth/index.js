import { User } from "../../models/user/register.js";
import Boom from "boom";
import Token from "../../models/token.js";
import sendEmail from "../../utils/sendEmail.js";
import crypto from "crypto";
import bcrypt from "bcrypt";
import { verificationMail } from "../../utils/mails/mailVerification.js";
// helpers
import {
  signAccessToken,
  signRefreshToken,
  verifyRefreshToken,
} from "../../middleware/jwt.js";

// validations
import dotenv from "dotenv";
dotenv.config();
import ValidationSchema from "./validation.js";
import redis from "../../clients/redis.js";



const Register = async (req, res, next) => {
  const input = req.body;

  const { error } = ValidationSchema.validate(input);

  if (error) {
    return res.status(400).send(error.details[0].message);
  }

  try {
    const isExists = await User.findOne({ email: input.email });

    if (isExists) {
      return res.status(400).send("Email already exists.");
    }

    const user = new User(input);
    const data = await user.save();
    const userData = data.toObject();

    delete userData.password;
    delete userData.__v;

    const accessToken = await signAccessToken({
      user_id: user._id,
      role: user.role,
    });
    const refreshToken = await signRefreshToken(user._id);

    const token = await new Token({
      userId: user._id,
      token: crypto.randomBytes(32).toString("hex"),
      token_type: "verification",
    }).save();

    const url = `${process.env.BASE_URL}user/${user._id}/verify/${token.token}`;
    
    await sendEmail(user.email, "Verify Email", verificationMail(url));

    res.cookie("refreshToken", refreshToken, {
      httpOnly: true,
      expires: new Date(Date.now() + 1000 * 60 * 60 * 24 * 7),
      secure: false,
      sameSite: "strict",
    });

    res.json({
      user: userData,
      accessToken,
      refreshToken,
    });
  } catch (e) {
    next(e);
  }
};

const Login = async (req, res, next) => {
  const input = req.body;

  const { error } = ValidationSchema.validate(input);

  if (error) {
    return res.status(400).send(error.details[0].message);
  }

  try {
    const user = await User.findOne({ email: input.email });

    if (!user) {
      return res.status(400).send("email or password not correct");
    }

    const isMatched = await user.isValidPass(input.password);
    if (!isMatched) {
      return res.status(400).send("email or password not correct");
    }

    const accessToken = await signAccessToken({
      user_id: user._id,
      role: user.role,
    });
    const refreshToken = await signRefreshToken(user._id);

    const userData = user.toObject();
    delete userData.password;
    delete userData.__v;

    // if (!user.email_verified) {
    //   let token = await Token.findOne({ userId: user._id });
    //   if (!token) {
    //     token = await new Token({
    //       userId: user._id,
    //       token: crypto.randomBytes(32).toString("hex"),
    //     }).save();

    //     const url = `${process.env.BASE_URL}user/${user._id}/verify/${token.token}`;

    //     await sendEmail(user.email, "Verify Email", verificationMail(url));
    //   }
    //   return resUserContext";
    //     .status(400)
    //     .send("An email has been sent to you to verify your account");
    // }

    res.cookie("refreshToken", refreshToken, {
      httpOnly: true,
      expires: new Date(Date.now() + 1000 * 60 * 60 * 24 * 7),
      secure: false,
      sameSite: "strict",
    });

    res.status(200).json({ user: userData, accessToken, refreshToken });
  } catch (e) {
    return next(e);
  }
};

const RefreshToken = async (req, res, next) => {
  let refresh_token = req.headers.cookie;
  refresh_token = refresh_token
    ?.split(";")
    .find((c) => c.trim().startsWith("refreshToken="))
    ?.split("=")[1];
  try {
    if (!refresh_token) {
      next(Boom.badRequest());
      console.log("refresh token");
    }

    const user_id = await verifyRefreshToken(refresh_token);
    const accessToken = await signAccessToken(user_id);
    const refreshToken = await signRefreshToken(user_id);
    res.cookie("refreshToken", refreshToken, {
      httpOnly: true,
      expires: new Date(Date.now() + 1000 * 60 * 60 * 24 * 7),
      secure: false,
      sameSite: "strict",
    });
    res.status(200).json({ accessToken, refreshToken, user_id });
  } catch (e) {
    next(Boom.badRequest());
    console.log("refresh token");
  }
};

const Logout = async (req, res, next) => {
  let refresh_token = req.headers.cookie;
  refresh_token = refresh_token
    ?.split(";")
    .find((c) => c.trim().startsWith("refreshToken="))
    ?.split("=")[1];
  try {
    if (!refresh_token) {
      throw Boom.badRequest();
    }

    const user_id = await verifyRefreshToken(refresh_token);
    const data = await redis.del(user_id);

    if (!data) {
      throw Boom.badRequest();
    }

    res.json({ message: "success" });
  } catch (e) {
    console.log(e);
    return next(e);
  }
};

const Me = async (req, res, next) => {
  const { user_id } = req.body;

  if (!user_id) {
    return res.status(400).send("user_id is required");
  }
  try {
    const user = await User.findById(user_id).select("-password -__v");

    res.json(user);
  } catch (e) {
    next(e);
  }
};

const verifyMail = async (req, res) => {
  const { id, token } = req.params;
  const tokenData = token;
  try {
    const user = await User.findOne({ _id: id });
    if (!user) {
      return res.status(404).json({ message: "Invalid Link" });
    }
    const token = await Token.findOne({
      userId: user._id,
      token: tokenData,
      token_type: "verification",
    });
    if (!token) {
      return res.status(404).json({ message: "Invalid Link" });
    }

    await User.updateOne({ _id: id }, { $set: { email_verified: true } });
    await Token.deleteOne({
      userId: user._id,
      token: tokenData,
      token_type: "verification",
    });

    res.status(200).json({ message: "Email Verified" });
  } catch (e) {
    return next(e);
  }
};

const forgetPassword = async (req, res, next) => {
  const { email } = req.body;

  try {
    const user = await User.findOne({ email });

    if (!user) {
      return res.status(400).send("email not found");
    }

    const token = await new Token({
      userId: user._id,
      token: crypto.randomBytes(32).toString("hex"),
      token_type: "forgetPassword",
    }).save();

    const url = `${process.env.BASE_URL}user/${user._id}/reset/${token.token}`;
    await sendEmail(user.email, "Reset Password", url);

    res.json({
      message: "an email has been sent to you to reset your password",
    });
  } catch (e) {
    next(e);
  }
};

const resetPassword = async (req, res, next) => {
  const { id, token } = req.params;
  const { password } = req.body;
  try {
    const user = await User.findOne({ _id: id });
    if (!user) {
      return res.status(400).send("user not found");
    }

    const tokenData = await Token.findOne({
      userId: user._id,
      token,
      token_type: "forgetPassword",
    });
    if (!tokenData) {
      return res.status(400).send("invalid link");
    }

    const salt = await bcrypt.genSalt(10);
    const hashPassword = await bcrypt.hash(password, salt);

    await User.updateOne({ _id: id }, { $set: { password: hashPassword } });
    await Token.deleteOne({
      userId: user._id,
      token,
      token_type: "forgetPassword",
    });

    await sendEmail(
      user.email,
      "Reset Password",
      "Şifreniz başarıyla değiştirildi"
    );

    res.json({
      message: "password has been reset",
    });
  } catch (e) {
    next(e);
  }
};

const checkToken = async (req, res, next) => {
  const { id, token } = req.params;
  const { token_type } = req.body;

  try {
    const isExist = await Token.findOne({
      token,
      userId: id,
      token_type,
    });
    if (!isExist) {
      return res.status(400).send("invalid link");
    }

    res.status(200).send("valid link");
  } catch (e) {
    next(e);
  }
};

const newPassword = async (req, res, next) => {
  const { id } = req.params;
  const { oldPassword, password } = req.body;

  try {
    const user = await User.findOne({ _id: id });
    if (!user) {
      return res.status(400).send({ message: "Kullanıcı bulunamadı" });
    }

    const isMatch = await bcrypt.compare(oldPassword, user.password);
    if (!isMatch) {
      return res.status(400).send({ message: "Eski şifre hatalı" });
    }

    const salt = await bcrypt.genSalt(10);
    const hashPassword = await bcrypt.hash(password, salt);

    await User.updateOne({ _id: id }, { $set: { password: hashPassword } });

    res.json({ message: "Şifreniz başarılı bir şekilde güncellendi." });
  } catch (e) {
    next(e);
  }
};

export default {
  Register,
  Login,
  RefreshToken,
  Logout,
  Me,
  forgetPassword,
  verifyMail,
  resetPassword,
  checkToken,
  newPassword,
};
