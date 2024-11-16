const express = require("express");
const authController = require("../controllers/authController");
const Router = express.Router();
Router.post("/signup", authController.signup);
Router.post("/login", authController.login);
Router.get("/logout", authController.logOut);
Router.patch("/Sugar", authController.protect, authController.updateSugar);
Router.patch("/Bp", authController.protect, authController.updateBP);
Router.post("/upload", authController.protect, authController.uploadImage); 
Router.get("/images", authController.protect, authController.getUserImages);


// Router.patch("/update/:id", authController.protect,doctorController.update);
// Router.get(
//   "/me",
//   authController.protect,
//   authController.getMe,
//   authController.getUser
// );
// Router.get("/", doctorController.getAllDoctors);
//   .post(doctorController.createUser);
// Router.route("/:id")
//   .get(doctorController.getUser)
//   .patch(doctorController.updateUser)
//   .delete(doctorController.deleteUser);
module.exports = Router;
