import { Router } from "express";
import auth from "../controllers/auth/index.js";
import { verifyAccessToken } from "../middleware/jwt.js";
const router = Router();

router.post("/login", auth.Login);
router.post("/refresh_token", auth.RefreshToken);
router.post("/signup", auth.Register);
router.post("/me", verifyAccessToken, auth.Me);
router.post("/logout", auth.Logout);
router.post("/forgot_password", auth.forgetPassword);
router.get("/:id/verify/:token", auth.verifyMail);
router.post("/user/:id/token/:token", auth.checkToken);
router.post("/:id/reset/:token", auth.resetPassword);
router.post("/:id/change_password", verifyAccessToken, auth.newPassword);
export default router;
