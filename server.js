require("dotenv").config();
const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");
const bodyParser = require("body-parser");
const cookieParser = require("cookie-parser");
const userRoute = require("./routes/userRoute");
const errorHandler = require("./middleware/errorMiddleware");

const app = express();

//middlewares
app.use(express.json());
app.use(cookieParser());
app.use(express.urlencoded({ extended: false }));
app.use(bodyParser.json());

//prevent any conflicts with frontend an backend
app.use(
  cors({
    //localhost 3000 react
    origin: ["http://localhost:3000", "https://authz-app.vercel.app"],
    credentials: true,
  })
);

//routes middleware
// api/users userRoute imported api/users/register
app.use("/api/users", userRoute);

app.get("/", (req, res) => {
  res.send("home-page");
});

//error handler
app.use(errorHandler);

const PORT = process.env.PORT || 5000;

mongoose
  .connect(process.env.MONGO_URI)
  .then(() => {
    app.listen(PORT, () => {
      console.log(`Server running on ${PORT}`);
    });
  })
  .catch((err) => console.log(err));

//mongodb+srv://bader:<password>@baderdatabasecluster.645pwz4.mongodb.net/?retryWrites=true&w=majority
