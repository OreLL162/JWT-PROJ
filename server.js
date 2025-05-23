import express from 'express';
import mongoose from 'mongoose';
import cors from 'cors';
import dotenv from 'dotenv';
import cookieParser from 'cookie-parser';
import authRoutes from './routes/authRoutes.js';

dotenv.config();

const app = express();
app.use(cors({
    origin: 'http://localhost:5173', // frontend URL or Postman origin
    credentials: true
  }));
app.use(express.json());
app.use(cookieParser());



mongoose.connect(process.env.MONGO_URI)
  .then(() => console.log('MongoDB connected'))
  .catch(err => console.error(err));

  
app.use('/auth', authRoutes);

app.listen(process.env.PORT, () => console.log(`The server is running on port ${process.env.PORT}.`));