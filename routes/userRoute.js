import express from "express";
const router = express.Router();
import { getById, updateById } from "../controllers/userController";

router.get("/:id", getById).patch("/:id", updateById);

const userRoutes = router;
export default userRoutes;
