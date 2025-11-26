// sendOtpEmail.js
const nodemailer = require("nodemailer");

async function sendOtpEmail(toEmail, otp) {
    try {
        console.log("email",toEmail)
        
        const transporter = nodemailer.createTransport({
            service: "gmail",
            auth: {
                user: process.env.EMAIL_USER, 
                pass: process.env.EMAIL_PASS
            }
        });

        const mailOptions = {
            from: `"Your App" <${process.env.EMAIL_USER}>`,
            to: toEmail,
            subject: "Your OTP Code",
            html: `
                <h3>Your OTP Code</h3>
                <p>Your verification code is:</p>
                <h1>${otp}</h1>
                <p>This code will expire in <b>15 seconds</b>.</p>
            `
        };

        await transporter.sendMail(mailOptions);
        console.log("OTP sent to email:", toEmail);

    } catch (err) {
        console.log("Email sending failed:", err);
    }
}

module.exports = sendOtpEmail;
