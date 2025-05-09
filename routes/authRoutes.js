import express from 'express';
import { register, login,  verifyOTP } from '../controllers/authController.js';

const router = express.Router();

router.post('/register', register);
router.post('/login', login);
router.post('/verifyOTP', verifyOTP);

export default router;