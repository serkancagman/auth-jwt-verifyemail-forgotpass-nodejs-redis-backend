import mongoose from "mongoose";

const userSchema = new mongoose.Schema({
  email: {
    type: string,
    required: true,
  },
  password: {
    type: string,
    required: true,
  },
});
userSchema.methods.isValidPass = async function (pass) {
  return await bcrypt.compare(pass, this.password);
};
export const userLogin = mongoose.model("userLogin", userSchema);
