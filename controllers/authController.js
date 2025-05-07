import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import User from '../models/User.js';


export async function register(req, res) {
  
    try {
      const { username, email, password } = req.body;
  
      if (!username || !password || !email) {
        return res.status(400).json({ message: 'Provide Credentials' });
      }
  
      const existingUser = await User.findOne({ username });
      const existingEmail = await User.findOne({ email });
  
      if (existingUser) {
        return res.status(400).json({ message: 'User exists, please login' });
      }
  
      if (existingEmail) {
        return res.status(400).json({ message: 'This email is taken! please login with this email or try another one' });
      }
  
      const hashedPassword = await bcrypt.hash(password, 10);
  
      const newUser = await User.create({
        username,
        email,
        password: hashedPassword
        
      });
  
      return res.status(201).json({ msg: 'Registered.'});
  
    } catch (error) {
      console.error('Registration error:', error);
      return res.status(500).json({ message: 'Server error during registration' });
    }
  }


export async function login(req, res) {

    try {
        const { username, password ,email } = req.body;
        const user = await User.findOne({ username });
        if (!user || !(await bcrypt.compare(password, user.password)))
          return res.status(401).json({ msg: 'Invalid credentials' });
      
        await user.save();




    } catch ( error) {

    }


}