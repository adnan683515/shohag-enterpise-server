
require("dotenv").config();
const express = require("express");
const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const cookieParser = require("cookie-parser");
const nodemailer = require("nodemailer");
const cors = require("cors");
const sendOtpEmail = require("./sendOtp.js");
const { z } = require("zod");

const app = express();
app.use(cookieParser());
app.use(express.json());
app.use(cors());

//MONGODB CONNECT
mongoose
    .connect(process.env.DB_URL)
    .then(() => console.log("DB Connected"))
    .catch((err) => console.log("DB Error", err));

const transactionMongooseSchema = new mongoose.Schema({
    amount: { type: Number, required: true },
    date: { type: Date, default: Date.now },
    sender: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
    receiver: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
    createdBy: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
}, {
    timestamps: true, // still needed to auto-set createdAt/updatedAt internally
    toJSON: {
        virtuals: true,
        transform: (doc, ret) => {
            // Format createdAt
            if (ret.createdAt) {
                const d = new Date(ret.createdAt);
                const date = d.toISOString().split("T")[0];
                let hours = d.getHours();
                const minutes = d.getMinutes().toString().padStart(2, "0");
                const ampm = hours >= 12 ? "PM" : "AM";
                hours = hours % 12 || 12;
                ret.createdAtFormatted = `${date} , time: ${hours}:${minutes} ${ampm}`;
            }

            // Format updatedAt
            if (ret.updatedAt) {
                const d = new Date(ret.updatedAt);
                const date = d.toISOString().split("T")[0];
                let hours = d.getHours();
                const minutes = d.getMinutes().toString().padStart(2, "0");
                const ampm = hours >= 12 ? "PM" : "AM";
                hours = hours % 12 || 12;
                ret.updatedAtFormatted = `${date} , time: ${hours}:${minutes} ${ampm}`;
            }

            // REMOVE the original timestamps from output
            delete ret.createdAt;
            delete ret.updatedAt;
            delete ret.__v;

            return ret;
        }
    }
});

const UserSchema = new mongoose.Schema({
    name: String,
    email: String,
    password: String,
    role: { type: String, default: "user" },
    otp: { type: String, default: null },
    otpExpiresAt: { type: Date, default: null },
    isVerified: { type: Boolean, default: false }
});

function auth(req, res, next) {
    try {
        const token = req.headers.authorization?.split(" ")[1];

        if (!token) return res.status(401).json({ msg: "No token" });

        const decoded = jwt.verify(token, process.env.ACCESS_TOKEN_SECRET);

        req.user = decoded;

        next();

    } catch (err) {

        return res.status(401).json({ msg: "Invalid token kire" });
    }
}

const Transaction = mongoose.model("Transaction", transactionMongooseSchema);

// USER MODEL
const User = mongoose.model("User", UserSchema);

// only admin
function OnlyAdmin(req, res, next) {
    if (req?.user?.role !== 'admin') {
        return res.status(403).json({ msg: "Admin only" });
    }
    next()
}

// admin or subadmin
function adminOrSubadmin(req, res, next) {
    if (req.user.role === "admin" || req.user.role === "subadmin") {
        return next(); 
    }
    return res.status(403).json({ msg: "Access denied: Admin or Subadmin only" });
}

// ADMIN CREATE DEFAULT USER
async function seedAdmin() {
    const exists = await User.findOne({ email: "golamfaruk680@gmail.com" });
    if (!exists) {
        const hash = await bcrypt.hash("Admin@123", 10);
        await User.create({
            name: "Sohag",
            email: "golamfaruk680@gmail.com",
            password: hash,
            role: "admin",
            isVerified: true
        });
        console.log("Admin created: golamfaruk680@gmail.com / Admin@123");
    }
}
seedAdmin();

// see all users
app.get('/allUsers', auth, OnlyAdmin, async (req, res) => {
    console.log("Users get")
    try {
        const users = await User.find({}).select("_id name role");
        res.json({
            count: users.length,
            users
        });
    } catch (err) {
        console.error(err);
        res.status(500).json({ msg: "Server Error" });
    }
});

// otp verify
app.post("/verify-otp", async (req, res) => {
    const { email, otp } = req.body;

    const user = await User.findOne({ email });
    if (!user) return res.status(404).json({ msg: "User not found" });

    if (Date.now() > user.otpExpiresAt) {
        user.otp = null;
        user.otpExpiresAt = null;
        await user.save();
        return res.status(400).json({ msg: "OTP expired" });
    }

    if (user.otp !== otp) {
        return res.status(400).json({ msg: "Invalid OTP" });
    }

    user.isVerified = true;
    user.otp = null;
    user.otpExpiresAt = null;
    await user.save();

    res.json({ msg: "Verification successful! You can now login." });
});

// resend otp
app.post('/resendOtp', async (req, res) => {
    try {
        const email = req.cookies.userEmail;
        if (!email) {
            return res.status(400).json({ message: "Email not found in cookies" });
        }
        const user = await User.findOne({ email });
        if (!user) {
            return res.status(404).json({ message: "User not found" });
        }
        // Generate new OTP (4 digits)
        const newOtp = Math.floor(1000 + Math.random() * 9000).toString();
        // Set OTP expiry (2 minutes example)
        user.otp = newOtp;
        user.otpExpiresAt = new Date(Date.now() + 1 * 60 * 1000);
        await user.save();
        console.log("Updated User OTP:", newOtp);


        await sendOtpEmail(email, newOtp);

        res.status(200).json({
            success: true,
            message: "New OTP has been sent!",
            email,
        });

    } catch (error) {
        console.error(error);
        res.status(500).json({
            success: false,
            message: "Something went wrong",
            error: error.message,
        });
    }
});

// register user
app.post("/register", async (req, res) => {

    const { name, email, password } = req.body;
    const exists = await User.findOne({ email });
    if (exists) return res.status(400).json({ msg: "User already exists" });

    const hashed = await bcrypt.hash(password, 10);

    const otp = Math.floor(1000 + Math.random() * 9000).toString();
    const otpExpiresAt = Date.now() + 60000;

    await User.create({
        name,
        email,
        password: hashed,
        isVerified: false,
        otp,
        otpExpiresAt
    });

    res.cookie("userEmail", email, {
        httpOnly: true,
        secure: false,      // production e TRUE korba
        sameSite: "strict",
        path: "/",
        maxAge: 7 * 24 * 60 * 60 * 1000 // 7 days
    });




    const mailResult = await sendOtpEmail(email, otp);


    res.json({ msg: "OTP sent to email" });
});

// login user
app.post("/login", async (req, res) => {
    try {
        const { email, password } = req.body;

        const user = await User.findOne({ email });

        if (!user) return res.status(400).json({ msg: "Invalid email or password" });

        const ok = await bcrypt.compare(password, user.password);
        if (!ok) return res.status(400).json({ msg: "Invalid email or password" });

        // If email NOT verified — Stop Login
        if (!user.isVerified) {
            return res.status(401).json({
                msg: "Please verify your email before login!",
                status: "not_verified",
                email: user.email
            });
        }

        // CREATE ACCESS + REFRESH TOKEN
        const accessToken = jwt.sign(
            { id: user._id, email: user.email, role: user.role },
            process.env.ACCESS_TOKEN_SECRET,
            { expiresIn: "1h" }
        );

        const refreshToken = jwt.sign(
            { id: user._id },
            process.env.REFRESH_TOKEN_SECRET,
            { expiresIn: "7d" }
        );


        // SET REFRESH TOKEN IN COOKIE
        res.cookie("refreshToken", refreshToken, {
            httpOnly: true,
            secure: false,       // Production = true
            sameSite: "strict",
            maxAge: 7 * 24 * 60 * 60 * 1000
        });



        res.cookie("userEmail", email, {
            httpOnly: true,
            secure: false,      // production e TRUE korba
            sameSite: "strict",
            path: "/",
            maxAge: 7 * 24 * 60 * 60 * 1000 // 7 days
        });



        // SEND ACCESS TOKEN
        res.json({
            msg: "Login success",
            accessToken
        });

    } catch (err) {
        console.error(err);
        res.status(500).json({ msg: "Server error" });
    }
});

// LOGOUT USER
app.post("/logout", (req, res) => {
    res.clearCookie("refreshToken");
    res.clearCookie('userEmail')
    res.json({ msg: "Logged out" });
})

// transection zod validation
const transactionZod = z.object({
    amount: z.number().min(1, "Amount must be greater than 0"),
    date: z.string().optional(), // optional string, you can parse it later to Date
    sender: z.string().length(24, "Sender must be a valid MongoDB ObjectId"),
    receiver: z.string().length(24, "Receiver must be a valid MongoDB ObjectId"),
});

// admin add transaction
app.post("/transaction", auth, adminOrSubadmin, async (req, res) => {
    try {

        const parsed = transactionZod.safeParse(req.body)

        if (!parsed.success) {
            return res.status(400).json({ errors: parsed.error.errors });
        }

        const { amount, date, sender, receiver } = parsed.data;

        const txDate = date ? new Date(date) : new Date();

        const tx = await Transaction.create({
            amount,
            date: txDate,
            sender,
            receiver,
            createdBy: req.user.id,
        });

        res.json(tx);
    } catch (err) {
        console.error(err);
        res.status(500).json({ msg: "Server Error" });
    }
});

// Transaction Details
app.get('/transectionDetails/:id', auth, async (req, res) => {
    try {
        const { id } = req.params;

        const tx = await Transaction.findById(id)
            .populate("sender", "name email")
            .populate("receiver", "name email");

        if (!tx) {
            return res.status(404).json({ msg: "Transaction not found" });
        }

        res.json(tx);

    } catch (err) {
        console.error(err);
        res.status(500).json({ msg: "Server error" });
    }
});

// edit transection only subadmin and adnmin
app.put("/transaction/:id", auth, adminOrSubadmin, async (req, res) => {
    try {
        const { id } = req.params;
        const { amount, date, sender, receiver } = req.body;

        const updatedTx = await Transaction.findByIdAndUpdate(
            id,
            {
                amount,
                date,
                sender,
                receiver
            },
            { new: true, runValidators: true }
        )
            .populate("sender", "name email")
            .populate("receiver", "name email");

        if (!updatedTx) {
            return res.status(404).json({ msg: "Transaction not found" });
        }

        res.json({
            msg: "Transaction updated successfully",
            transaction: updatedTx
        });

    } catch (err) {
        console.error(err);
        res.status(500).json({ msg: "Server error" });
    }
});

app.get("/transaction", auth, async (req, res) => {
    try {
        const { user, sender, receiver } = req.query;
        let query = {};
        // Single user filter → sender OR receiver
        if (user) {
            query = {
                $or: [
                    { sender: user },
                    { receiver: user }
                ]
            };
        }

        // If both sender & receiver filter provided → exact between 2 users
        if (sender && receiver) {
            query = {
                $or: [
                    { sender, receiver },
                    { sender: receiver, receiver: sender }
                ]
            };
        }

        const list = await Transaction.find(query)
            .populate("sender", "name email")
            .populate("receiver", "name email")
            .sort({ date: -1 });

        return res.json(list);

    } catch (err) {
        console.error(err);
        res.status(500).json({ msg: "Server error" });
    }
});

app.get('/', (req, res) => {
    res.send(`server running port ${process.env.PORT} `)
})
app.listen(5000, () => console.log("Server running on 5000"));