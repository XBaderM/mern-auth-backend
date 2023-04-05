const express = require("express");
const router = express.Router();

const {
  registerUser,
  loginUser,
  logoutUser,
  getUser,
  updateUser,
  deleteUser,
  getUsers,
  loginStatus,
  upgradeUser,
  sendAutomatedEmail,
  sendVerificationEmail,
  verifyUser,
  forgotPassword,
  resetPassword,
  changePassword,
  sendLoginCode,
  loginWithCode,
  loginWithGoogle,
} = require("../controllers/userController");
const {
  protect,
  adminOnly,
  authorOnly,
} = require("../middleware/authMiddleware");

//register path = controller registerUser
router.post("/register", registerUser);
//"login path" controller loginuser function in controllers
router.post("/login", loginUser);

router.get("/logout", logoutUser);

//using middle protect function from before get user validating (auth middleware)
//protect route
router.get("/getUser", protect, getUser);
router.get("/getUsers", protect, authorOnly, getUsers);
router.get("/loginStatus", loginStatus);

router.patch("/updateUser", protect, updateUser);
router.delete("/:id", protect, adminOnly, deleteUser);
router.post("/upgradeUser", protect, adminOnly, upgradeUser);
router.post("/sendAutomatedEmail", protect, sendAutomatedEmail);
router.post("/sendVerificationEmail", protect, sendVerificationEmail);
//sending the verification from the frontend to backend as params
router.patch("/verifyUser/:verificationToken", verifyUser);
router.post("/forgotPassword", forgotPassword);
router.patch("/resetPassword/:resetToken", resetPassword);
//user loged in before change password ie protect
router.patch("/changePassword", protect, changePassword);
//no protect because user is not logged in fully
router.post("/sendLoginCode/:email", sendLoginCode);
router.post("/loginWithCode/:email", loginWithCode);

router.post("/google/callback", loginWithGoogle);
module.exports = router;
