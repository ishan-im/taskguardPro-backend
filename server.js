//Third party package imports
const dotenv = require("dotenv");
const mongoose = require("mongoose");

process.on("uncaughtException", (err) => {
  console.log("Uncaught Exception\n", err);
  process.exit(1);
});

/*Loads environment variables. this needs to be configured before requiring app,
else env variables won't be available in app.js*/
dotenv.config();

//imports from project code
const app = require("./app");

const DB = process.env.DATABASE.replace(
  "<password>",
  process.env.DATABASE_PASSWORD
);

mongoose.connect(DB).then(() => {
  console.log("DB connected succesfully.");
});

const server = app.listen(process.env.PORT, () => {
  console.log(`Listening on PORT ${process.env.PORT}`);
});

process.on("unhandledRejection", (err) => {
  console.error("Unhandled Rejection\n", err);
  server.close(() => process.exit(1));
});
