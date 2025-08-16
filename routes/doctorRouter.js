const express = require("express");
const doctorController = require("../controllers/doctorController");
// Import the PROTECT function from the USER controller
const authController =require( '../controllers/authController');
const { protect } = require("../controllers/authController"); 

const router = express.Router();

router.post("/signup", doctorController.signup);
router.post("/login", doctorController.login);
router.get("/", doctorController.getAllDoctors);



// The 'update' route is for a patient to book an appointment, so it should be protected too
// It checks for a logged-in user (patient OR doctor) and then lets them update
router.patch("/update/:id", protect, doctorController.update);

module.exports = router;