import express from "express";
import cors from "cors";
import dotenv from "dotenv";
import mongoose from "mongoose";
import morgan from "morgan";
import cookieParser from "cookie-parser";
import authRoutes from "./routes/authRoutes.js";
import userRoutes from "./routes/userRoute.js";

dotenv.config();

const app = express();
const port = process.env.PORT;
const db = process.env.DB;

// db connection
mongoose
  .connect(db, {})
  .then(() => {
    console.log("Connected to db");
  })
  .catch((error) => {
    console.log("Error:", error);
  });

// middlewares
app.use(
  cors({
    origin: process.env.ORIGIN,
    credentials: true,
    exposedHeaders: ["X-Total-Count"],
    methods: ["GET", "POST", "PATCH", "DELETE"],
  }),
);
app.use(express.json());
app.use(cookieParser());
app.use(morgan("tiny"));

// route middleware
app.use("/auth", authRoutes);
app.use("/users", userRoutes);

app.get("/", (req, res) => {
  res.status(200).json({ message: "running" });
});

app.listen(port, () => {
  console.log("Server running on http://localhost:8080");
});
