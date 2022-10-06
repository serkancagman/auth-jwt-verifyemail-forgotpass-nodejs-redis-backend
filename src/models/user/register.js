import mongoose from "mongoose";
import bcrypt from "bcrypt";
const userSchema = new mongoose.Schema({
  name: {
    type: String,
    required: false,
  },
  surname: {
    type: String,
    required: false,
  },
  country: {
    type: String,
    required: false,
  },
  email_verified: {
    type: Boolean,
    required: false,
  },
  phone: {
    type: String,
    required: false,
  },
  email: {
    type: String,
    required: true,
    unique: true,
  },
  password: {
    type: String,
    required: true,
  },
  createdAt: {
    type: Date,
    default: Date.now,
  },
  updatedAt: {
    type: Date,
    default: Date.now,
  },
  account_type: {
    type: String,
    required: true,
    default: "standart",
  },
  role: {
    type: String,
    default: "user",
    enum: ["user", "admin"],
  },
});

userSchema.pre("save", async function (next) {
  try {
    if (this.isNew) {
      const saltedPassword = await bcrypt.genSalt(10);
      const hashedPassword = await bcrypt.hash(this.password, saltedPassword);
      this.password = hashedPassword;
      next();
    }
  } catch (err) {
    next(err);
  }
});

userSchema.methods.isValidPass = async function (pass) {
  return await bcrypt.compare(pass, this.password);
};
export const User = mongoose.model("User", userSchema);
