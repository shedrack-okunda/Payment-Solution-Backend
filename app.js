import express from "express";
import cors from "cors";
import dotenv from "dotenv";
import mongoose from "mongoose";

dotenv.config();

const app = express();
const db = process.env.DB;

app.use(cors());
app.use(express.json());

// db connection
mongoose
  .connect(db, {})
  .then(() => {
    console.log("Connected to db");
  })
  .catch((error) => {
    console.log("Error:", error);
  });

app.listen(8080, () => {
  console.log("Server running on http://localhost:8080");
});
