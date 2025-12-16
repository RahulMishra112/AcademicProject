const express = require("express");
const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const asyncHandler = require("express-async-handler");
require("dotenv").config();

const app = express();
app.use(express.json());


const PORT = process.env.PORT || 3000;
const MONGO_URI = process.env.MONGO_URI || "mongodb://127.0.0.1:27017/etms";
const JWT_SECRET = process.env.JWT_SECRET || "secret123";
const DEFAULT_ADMIN_PASS = process.env.DEFAULT_ADMIN_PASS || "admin123";


mongoose
  .connect(MONGO_URI)
  .then(() => console.log("MongoDB connected"))
  .catch((err) => console.error("DB connection error:", err));


const safeJson = (res, status, data) => {
  return res.status(status).json(data);
};

const UserSchema = ne

  username: { type: String, unique: true, required: true },
  passwordHash: { type: String, required: true },
  role: { type: String, enum: ["admin", "manager"], default: "manager" },
});


const EmployeeSchema = new mongoose.Schema({
  name: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  department: String,
  createdAt: { type: Date, default: Date.now },
});


const TimeEntrySchema = new mongoose.Schema({
  employee: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "Employee",
    required: true,
  },

  clockIn: {
    type: Date,
    required: true,
  },

  clockOut: {
    type: Date,
    validate: {
      validator: function (value) {
        return !value || value > this.clockIn;
      },
      message: "Clock-out must be after clock-in",
    },
  },

  durationMinutes: {
    type: Number,
    min: 0,
    default: 0,
  },

  note: {
    type: String,
    maxlength: 500,
    trim: true,
  },

  source: {
    type: String,
    enum: ["web", "manual", "api", "mobile"],
    default: "web",
  },

  createdAt: {
    type: Date,
    default: Date.now,
  },
});

TimeEntrySchema.index({ employee: 1, createdAt: -1 });


const User = mongoose.model("User", UserSchema);
const Employee = mongoose.model("Employee", EmployeeSchema);
const TimeEntry = mongoose.model("TimeEntry", TimeEntrySchema);

async function createAdminIfMissing() {
  try {
    const count = await User.countDocuments();
    if (count === 0) {
      const hash = await bcrypt.hash(DEFAULT_ADMIN_PASS, 10);
      await User.create({
        username: "admin",
        passwordHash: hash,
        role: "admin",
      });
      console.log(
        "Default admin created → username: admin password:",
        DEFAULT_ADMIN_PASS
      );
    }
  } catch (err) {
    console.error("Admin creation error:", err.message);
  }
}

createAdminIfMissing();

const authMiddleware = asyncHandler(async (req, res, next) => {
  const auth = req.headers.authorization;

  if (!auth || !auth.startsWith("Bearer ")) {
    return safeJson(res, 401, { error: "Authorization token missing" });
  }

  try {
    const decoded = jwt.verify(auth.slice(7), JWT_SECRET);
    if (!decoded.id || !decoded.role) {
      return safeJson(res, 401, { error: "Invalid token payload" });
    }
    req.user = decoded;
    next();
  } catch {
    return safeJson(res, 401, { error: "Invalid or expired token" });
  }
});

const requireRole = (roles) =>
  asyncHandler(async (req, res, next) => {
    if (!roles.includes(req.user.role)) {
      return safeJson(res, 403, { error: "Forbidden" });
    }
    next();
  });


app.get("/", (req, res) => {
  res.send("Employee Time Management API is running");
});



app.post(
  "/api/auth/login",
  asyncHandler(async (req, res) => {
    const { username, password } = req.body;

    if (!username || !password) {
      return safeJson(res, 400, { error: "All fields required" });
    }

    const user = await User.findOne({ username });
    if (!user) return safeJson(res, 401, { error: "Invalid credentials" });

    const match = await bcrypt.compare(password, user.passwordHash);
    if (!match) return safeJson(res, 401, { error: "Invalid credentials" });

    const token = jwt.sign(
      { id: user._id, role: user.role },
      JWT_SECRET,
      { expiresIn: "1d" }
    );

    safeJson(res, 200, { token });
  })
);


app.post(
  "/api/employees",
  authMiddleware,
  requireRole(["admin", "manager"]),
  asyncHandler(async (req, res) => {
    const { name, email, department } = req.body;

    if (!name || !email) {
      return safeJson(res, 400, { error: "Name and email required" });
    }

    const employee = await Employee.create({ name, email, department });
    safeJson(res, 201, employee);
  })
);


app.post(
  "/api/time-entry/clock-in",
  authMiddleware,
  asyncHandler(async (req, res) => {
    const { employeeId } = req.body;

    const entry = await TimeEntry.create({
      employee: employeeId,
      clockIn: new Date(),
    });

    safeJson(res, 201, entry);
  })
);

app.post(
  "/api/time-entry/clock-out/:id",
  authMiddleware,
  asyncHandler(async (req, res) => {
    const entry = await TimeEntry.findById(req.params.id);
    if (!entry) return safeJson(res, 404, { error: "Entry not found" });

    entry.clockOut = new Date();
    entry.durationMinutes = Math.floor(
      (entry.clockOut - entry.clockIn) / 60000
    );

    await entry.save();
    safeJson(res, 200, entry);
  })
);


app.use((err, req, res, next) => {
  console.error(err);
  safeJson(res, 500, { error: "Server error" });
});


app.listen(PORT, () =>
  console.log(`Server running on http://localhost:${PORT}`)
);

