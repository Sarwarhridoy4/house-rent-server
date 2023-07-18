const express = require("express");
const mongoose = require("mongoose");
const jwt = require("jsonwebtoken");
const cors = require("cors");
const bcrypt = require("bcrypt");
require("dotenv").config();
const SECRET = process.env.SECRET_KEY; // Secre
const URL = `mongodb+srv://${process.env.DB_USER}:${process.env.DB_PASS}@cluster0.9rpk71q.mongodb.net/house_rental_db?retryWrites=true&w=majority`
const app = express();
app.use(express.json());
app.use(cors());

// Connect to MongoDB
mongoose
  .connect(
    URL,
    {
      useNewUrlParser: true,
      useUnifiedTopology: true,
    }
  )
  .then(console.log("Database Connected"))
  .catch((err) => console.log("Error is:", err));

const db = mongoose.connection;
db.on("error", console.error.bind(console, "MongoDB connection error:"));

const userSchema = new mongoose.Schema({
  fullName: {
    type: String,
    required: true,
  },
  role: {
    type: String,
    enum: ["House Owner", "House Renter"],
    required: true,
  },
  phoneNumber: {
    type: String,
    required: true,
    unique: true,
  },
  email: {
    type: String,
    required: true,
    unique: true,
  },
  password: {
    type: String,
    required: true,
  },
});

userSchema.pre("save", async function (next) {
  const user = this;
  if (!user.isModified("password")) return next();

  const salt = await bcrypt.genSalt(10);
  const hash = await bcrypt.hash(user.password, salt);
  user.password = hash;
  next();
});

const User = mongoose.model("User", userSchema);

app.post("/register", async (req, res) => {
  try {
    const { fullName, role, phoneNumber, email, password } = req.body;
    const user = new User({ fullName, role, phoneNumber, email, password });
    await user.save();
      res.status(201).json({ message: "User registered successfully." });
  } catch (err) {
    res.status(500).json({ error: "Error registering user." });
  }
});

app.post("/login", async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ email });

    if (!user) {
      return res.status(404).json({ error: "User not found." });
    }

    const isPasswordValid = await bcrypt.compare(password, user.password);

    if (!isPasswordValid) {
      return res.status(401).json({ error: "Invalid credentials." });
    }

    const token = jwt.sign({ id: user._id }, SECRET, { expiresIn: "1h" });

    res.json({ token });
  } catch (err) {
    res.status(500).json({ error: "Error authenticating user." });
  }
});

function authenticateToken(req, res, next) {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];

  if (!token) {
    return res.status(401).json({ error: "No token provided." });
  }

  jwt.verify(token, SECRET_KEY, (err, user) => {
    if (err) {
      return res.status(403).json({ error: "Invalid token." });
    }
    req.user = user;
    next();
  });
}

// Protected route example
app.get("/protected", authenticateToken, (req, res) => {
  res.json({ message: "This is a protected route." });
});

app.get("/", async (req, res) => {
  res.send({ message: `House Rent Server Running on port :${PORT}` });
});

const PORT = 5000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
