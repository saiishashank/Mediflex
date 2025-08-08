const morgan = require("morgan");
const path = require("path");
const express = require("express");
const app = express();
const cors = require("cors");
const doctorRouter = require("./routes/doctorRouter");
const userRouter = require("./routes/userRoutes");
const authRouter =require("./routes/authroutes");
const bodyParser = require('body-parser');
app.use(cors());
app.use(express.urlencoded({ extended: true }));
app.use(morgan("dev"));
app.use(express.json());
app.use(bodyParser.json({ limit: '10mb' }));
app.use(bodyParser.urlencoded({ limit: '10mb', extended: true }));

app.use((req, res, next) => {
  req.requestTime = new Date().toISOString();
  next();
});
app.use("/api/doctor", doctorRouter);
app.use("/api/user", userRouter);
app.use("/api/auth", authRouter);
module.exports = app;
