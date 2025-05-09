export function otpEmailText(username, otp) {
    return `
  Hello ${username},
  
  You have requested to log in to your JWT-App account. Please use the One-Time Password (OTP) below to continue:
  
      🔐 OTP: ${otp}
  
  This code is valid for the next 5 minutes.
  
  If you did not initiate this request, please ignore this email.
  
  Thank you,  
  JWT-App Team
    `;
  }