const express = require("express");
const doctorController = require("../controllers/doctorController");
const authController = require("../controllers/authController");
const Router = express.Router();
Router.post("/signup", doctorController.signup);
Router.post("/login", doctorController.login);
// Router.get("/logout", authController.logOut);

Router.patch("/update/:id", authController.protect, doctorController.update);
Router.get(
  "/me",
  doctorController.protect,
  doctorController.getMe,
  doctorController.getUser
);
Router.get("/",doctorController.getAllDoctors);
//   .post(doctorController.createUser);
// Router.route("/:id")
//   .get(doctorController.getUser)
//   .patch(doctorController.updateUser)
//   .delete(doctorController.deleteUser);
module.exports = Router;
