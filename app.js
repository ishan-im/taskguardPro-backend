//Third party package imports
const express = require("express");
const cors = require("cors");
const cookieParser = require("cookie-parser");
const morgan = require("morgan");

//imports from project code

const userRouter = require("./routes/userRoutes");
const globalErrorHandler = require("./controllers/errorController");
const AppError = require("./utils/appError");

const app = express(); //Creating the express server

app.use(cors());

if (process.env.NODE_ENV === "development") {
  app.use(morgan("dev"));
}

/*This makes public directory the root for serving static file,
request can be done to http://localhost:port/path to get the static file.
app.use(express.static(`${__dirname}/public`));
*/

app.use(express.json());



app.use("/api/v1/users", userRouter);

app.all("*", (req, res, next) => {
  next(new AppError(`Couldn't find ${req.originalUrl} on this server!`, 404));
});

app.use(globalErrorHandler);

module.exports = app;
