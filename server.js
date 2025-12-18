/**
 * Employee Time Management System
 * Backend Server
 */

require("dotenv").config();
const express = require("express");
const mongoose = require("mongoose");
const bodyParser = require("body-parser");
const morgan = require("morgan");
const cors = require("cors");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");

const APP_PORT = process.env.PORT || 5000;
const MONGO_URI = process.env.MONGO_URI;
const JWT_SECRET = process.env.JWT_SECRET || "change_this_secret";
const DEFAULT_ADMIN_PASS = process.env.DEFAULT_ADMIN_PASS || "admin123";

const app = express();


app.use(cors());
app.use(bodyParser.json({ limit: "5mb" }));
app.use(bodyParser.urlencoded({ extended: true }));
app.use(morgan("dev"));

// Request time logger
app.use((req, res, next) => {
  req._startTime = Date.now();
  res.on("finish", () => {
    console.log(
      `${req.method} ${req.originalUrl} ${res.statusCode} - ${Date.now() - req._startTime}ms`
    );
  });
  next();
});


const nowUTC = () => new Date();
const safeJson = (res, code, data) => res.status(code).json(data);

const asyncHandler = (fn) => (req, res, next) =>
  Promise.resolve(fn(req, res, next)).catch(next);

const isValidObjectId = (id) => mongoose.Types.ObjectId.isValid(id);

const minutesBetween = (a, b) =>
  Math.round((b.getTime() - a.getTime()) / 60000);



mongoose.set("strictQuery", true);

const UserSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  passwordHash: { type: String, required: true },
  role: {
    type: String,
    enum: ["admin", "manager", "employee"],
    default: "employee",
  },
  createdAt: { type: Date, default: nowUTC },
});

const EmployeeSchema = new mongoose.Schema({
  name: { type: String, required: true },
  email: String,
  department: String,
  position: String,
  createdAt: { type: Date, default: nowUTC },
});

const TimeEntrySchema = new mongoose.Schema({
  employee: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "Employee",
    required: true,
  },
  clockIn: { type: Date, required: true },
  clockOut: Date,
  durationMinutes: { type: Number, default: 0 },
  createdAt: { type: Date, default: nowUTC },
});

const User = mongoose.model("User", UserSchema);
const Employee = mongoose.model("Employee", EmployeeSchema);
const TimeEntry = mongoose.model("TimeEntry", TimeEntrySchema);


async function createAdminIfMissing() {
  const count = await User.countDocuments();
  if (count === 0) {
    const hash = await bcrypt.hash(DEFAULT_ADMIN_PASS, 10);
    await User.create({
      username: "admin",
      passwordHash: hash,
      role: "admin",
    });
    console.log("Default admin created (username: admin)");
  }
}



const authMiddleware = asyncHandler(async (req, res, next) => {
  const auth = req.headers.authorization;
  if (!auth?.startsWith("Bearer "))
    return safeJson(res, 401, { error: "Missing token" });

  try {
    req.user = jwt.verify(auth.slice(7), JWT_SECRET);
    next();
  } catch {
    return safeJson(res, 401, { error: "Invalid token" });
  }
});


app.get("/", (req, res) =>
  res.send("Employee Time Management API is running")
);

// ---------- AUTH ----------
app.post(
  "/api/auth/login",
  asyncHandler(async (req, res) => {
    const { username, password } = req.body;

    if (!username || !password)
      return safeJson(res, 400, { error: "Username & password required" });

    const user = await User.findOne({ username });
    if (!user || !(await bcrypt.compare(password, user.passwordHash)))
      return safeJson(res, 401, { error: "Invalid credentials" });

    const token = jwt.sign(
      { id: user._id, role: user.role },
      JWT_SECRET,
      { expiresIn: "8h" }
    );

    safeJson(res, 200, { token });
  })
);

// ---------- EMPLOYEES ----------
app.post(
  "/api/employees",
  authMiddleware,
  asyncHandler(async (req, res) => {
    if (!req.body.name)
      return safeJson(res, 400, { error: "Employee name required" });

    const emp = await Employee.create(req.body);
    safeJson(res, 201, emp);
  })
);

// ---------- TIME TRACKING ----------
app.post(
  "/api/time/clockin",
  authMiddleware,
  asyncHandler(async (req, res) => {
    const { employeeId } = req.body;
    if (!isValidObjectId(employeeId))
      return safeJson(res, 400, { error: "Invalid employee ID" });

    const open = await TimeEntry.findOne({
      employee: employeeId,
      clockOut: null,
    });

    if (open)
      return safeJson(res, 409, { error: "Already clocked in" });

    const entry = await TimeEntry.create({
      employee: employeeId,
      clockIn: nowUTC(),
    });

    safeJson(res, 201, entry);
  })
);

app.post(
  "/api/time/clockout",
  authMiddleware,
  asyncHandler(async (req, res) => {
    const { employeeId } = req.body;

    const entry = await TimeEntry.findOne({
      employee: employeeId,
      clockOut: null,
    });

    if (!entry)
      return safeJson(res, 400, { error: "No active clock-in found" });

    entry.clockOut = nowUTC();
    entry.durationMinutes = minutesBetween(entry.clockIn, entry.clockOut);
    await entry.save();

    safeJson(res, 200, entry);
  })
);

app.use("/api", (req, res) => {
  safeJson(res, 404, { error: "Endpoint not found" });
});


app.use((err, req, res, next) => {
  console.error("Server Error:", err);
  safeJson(res, 500, { error: "Internal Server Error" });
});


mongoose
  .connect(MONGO_URI)
  .then(async () => {
    console.log("MongoDB Connected");
    await createAdminIfMissing();
    app.listen(APP_PORT, () =>
      console.log(`Server running on http://localhost:${APP_PORT}`)
    );
  })
  .catch((err) => {
    console.error("MongoDB Error:", err);
    process.exit(1);
  });
