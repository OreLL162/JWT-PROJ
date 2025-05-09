import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import User from '../models/User.js';
import sendEmail from '../utils/sendEmail.js';
import { otpEmailText } from '../utils/emailTemplates.js';



function generateOTP() {
    return Math.floor(100000 + Math.random() * 900000).toString(); // 6-digit OTP
  }

function generateToken(user) {
    return (
        jwt.sign(
            { id: user._id.toString(), username: user.username },
            process.env.JWT_SECRET,
            { expiresIn: '1h' }
          ));
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
        


        // send the OTP email
        const emailBody = otpEmailText(existingUser.username, otp);
        await sendEmail(existingUser.email, 'Your OTP Code', emailBody);



        // console.log(`OTP for ${username} sent to ${existingUser.email}`);
        return res.json({ msg: 'OTP sent to email' });

    } catch (error) {
        console.error('Login error:', error);
        return res.status(500).json({ message: 'Server error during Login' });
    }
}

export async function verifyOTP(req, res){

    try {
        const {username, otp} = req.body; 
        const user = await User.findOne({ username });
        
        // Cant find the user 
        if(!user) {
            return res.status(401).json({msg: "User was not found"})
        }

        // Provided Wrong or expired OTP
        if( user.otp !== otp || Date.now() > user.otpExpires) {
            return res.status(401).json({ msg: 'Invalid or expired OTP' });
        }
        
        // Clear OTP 
        user.otp = null;
        user.otpExpires = null;
        await user.save(); 

        //Produce JWT to user
        const token = generateToken(user);
    
        res.cookie('access_token', token, {
            httpOnly: true,
            secure: true,
            sameSite: 'Strict',
            maxAge: 60 * 60 * 1000
          });
        
        console.log(` Token successfully created for user ${user.username}`);
        return res.status(200).json({ msg: 'Login successful, token set in cookies' });

    } catch (error) {

        console.error('Login error:', error);
        return res.status(500).json({ message: 'Server error during Login' });
    }
}

