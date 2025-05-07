import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import User from '../models/User.js';


function generateOTP() {
    return Math.floor(100000 + Math.random() * 900000).toString(); // 6-digit OTP
  }

export async function register(req, res) {
  
    try {
      const { username, email, password } = req.body;
  
      if (!username || !password || !email) {
        return res.status(400).json({ message: 'Provide all Credentials' });
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


export async function login(req, res) { // When user Loggin in, he recieves OTP (one time password) to email 
                                        // after enteting OTP, the user gets his access token and refresh token

    try {
        const { username, email ,password } = req.body;

        if ( !username || !email || !password){
            return res.status(400).json({ message: 'Provide all Credentials' });
        }

        const existingUser = await User.findOne({ username ,email });

        if (!existingUser || !(await bcrypt.compare(password, existingUser.password)) ) {
          return res.status(401).json({ msg: 'Invalid credentials' });
        }

        const otp = generateOTP();
        existingUser.otp = otp;
        existingUser.otpExpires = Date.now() + 300000;
        await existingUser.save();
    
        console.log(`OTP for ${username}: ${otp}`);
        res.json({ msg: 'OTP sent' });

    } catch (error) {
        console.error('Login error:', error);
        return res.status(500).json({ message: 'Server error during Login' });
    }
}