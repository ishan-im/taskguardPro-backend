const { Router } = require("express");
const authController = require("../controllers/authController");
const userController = require("../controllers/userController");

const router = Router();

router.post("/signup", authController.signup);
router.post("/login", authController.login);
router.post("/forgotPassword", authController.forgotPassword);

router.route("/").get(authController.protect, userController.getAllUser);

module.exports = router;
