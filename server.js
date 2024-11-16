const app = require("./app");
const dotenv = require("dotenv");
const mongoose = require("mongoose");

dotenv.config({ path: "./config.env" });

const DB = process.env.DATABASE;

mongoose
  .connect(DB, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
  })
  .then(() => console.log("DB connection successful"))
  .catch((err) => {
    console.error("DB connection error:", err);
  });

const PORT = process.env.PORT || 8000; // Default to port 8000 if PORT is not defined in .env

app.listen(PORT, () => {
  console.log(`App running on port ${PORT}`);
});
