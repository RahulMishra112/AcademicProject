
const express = require("express");
const mongoose = require("mongoose");
const bodyParser = require("body-parser");
const morgan = require("morgan");
const cors = require("cors");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const { stringify } = require("csv-stringify/sync");

const APP_PORT = process.env.PORT || 5000;
const MONGO_URI =
  process.env.MONGO_URI ||
  "mongodb+srv://amarmishragonda334_db_user:db_%21bG2yxRmtXJL@cluster0.xwqfred.mongodb.net/EMS?retryWrites=true&w=majority&appName=Cluster0";

const JWT_SECRET = process.env.JWT_SECRET || "change_this_secret";
const DEFAULT_ADMIN_PASS = process.env.DEFAULT_ADMIN_PASS || "admin123";

const app = express();

app.use(cors());
app.use(bodyParser.json({ limit: "5mb" }));
app.use(bodyParser.urlencoded({ extended: true }));
app.use(morgan("dev"));

app.use((req, res, next) => {
  req._startTime = Date.now();
  res.on("finish", () => {
    console.log(
      `${req.method} ${req.originalUrl} ${res.statusCode} - ${
        Date.now() - req._startTime
      }ms`
    );
  });
  next();
});

function nowUTC() {
  return new Date();
}

function safeJson(res, code, data) {
  return res.status(code).json(data);
}

const asyncHandler = (fn) => (req, res, next) =>
  Promise.resolve(fn(req, res, next)).catch(next);

function toISONoMs(d) {
  if (!d) return "";
  return new Date(d).toISOString().replace(/\.\d{3}Z$/, "Z");
}

function minutesBetween(a, b) {
  return Math.round((b.getTime() - a.getTime()) / 60000);
}

function isValidObjectId(id) {
  return mongoose.Types.ObjectId.isValid(id);
}

function parsePagination(req) {
  const page = Math.max(1, parseInt(req.query.page || "1"));
  const limit = Math.min(200, Math.max(1, parseInt(req.query.limit || "50")));
  return { page, limit, skip: (page - 1) * limit };
}


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
  note: String,
  source: {
    type: String,
    enum: ["web", "manual", "api", "mobile"],
    default: "web",
  },
  createdAt: { type: Date, default: nowUTC },
});

TimeEntrySchema.index({ employee: 1, createdAt: -1 });

const User = mongoose.model("User", UserSchema);
const Employee = mongoose.model("Employee", EmployeeSchema);
const TimeEntry = mongoose.model("TimeEntry", TimeEntrySchema);


async function createAdminIfMissing() {
  const count = await User.countDocuments();
  if (count === 0) {
    const salt = await bcrypt.genSalt(10);
    const hash = await bcrypt.hash(DEFAULT_ADMIN_PASS, salt);
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

const requireRole = (roles) =>
  asyncHandler(async (req, res, next) => {
    if (!req.user) return safeJson(res, 401, { error: "Unauthorized" });
    if (!roles.includes(req.user.role))
      return safeJson(res, 403, { error: "Forbidden" });
    next();
  });


app.get("/", (req, res) => {
  res.send("Employee Time Management API is running. Use /api endpoints.");
});

app.get("/favicon.ico", (req, res) => res.status(204).end());


app.post(
  "/api/auth/register",
  asyncHandler(async (req, res) => {
    const { username, password, role } = req.body;

    if (!username || !password)
      return safeJson(res, 400, { error: "Username & password required" });

    const exists = await User.findOne({ username });
    if (exists) return safeJson(res, 409, { error: "Username exists" });

    const salt = await bcrypt.genSalt(10);
    const hash = await bcrypt.hash(password, salt);

    const user = await User.create({
      username,
      passwordHash: hash,
      role: role || "employee",
    });

    return safeJson(res, 201, { id: user._id });
  })
);

app.post(
  "/api/auth/login",
  asyncHandler(async (req, res) => {
    const { username, password } = req.body;

    const user = await User.findOne({ username });
    if (!user) return safeJson(res, 401, { error: "Invalid credentials" });

    const ok = await bcrypt.compare(password, user.passwordHash);
    if (!ok) return safeJson(res, 401, { error: "Invalid credentials" });

    const token = jwt.sign(
      { id: user._id, username: user.username, role: user.role },
      JWT_SECRET,
      { expiresIn: "8h" }
    );

    return safeJson(res, 200, { token });
  })
);

app.get(
  "/api/auth/me",
  authMiddleware,
  asyncHandler(async (req, res) => {
    const user = await User.findById(req.user.id).select("-passwordHash");
    return safeJson(res, 200, user);
  })
);


app.post(
  "/api/employees",
  authMiddleware,
  requireRole(["admin", "manager"]),
  asyncHandler(async (req, res) => {
    const { name, email, department, position } = req.body;
    if (!name) return safeJson(res, 400, { error: "Name required" });
    const emp = await Employee.create({ name, email, department, position });
    return safeJson(res, 201, emp);
  })
);

app.get(
  "/api/employees",
  authMiddleware,
  asyncHandler(async (req, res) => {
    const { page, limit, skip } = parsePagination(req);
    const q = req.query.q;
    const filter = q ? { name: { $regex: q, $options: "i" } } : {};
    const docs = await Employee.find(filter)
      .skip(skip)
      .limit(limit)
      .sort({ createdAt: -1 });
    const total = await Employee.countDocuments(filter);
    return safeJson(res, 200, { total, page, limit, docs });
  })
);

app.get(
  "/api/employees/:id",
  authMiddleware,
  asyncHandler(async (req, res) => {
    const id = req.params.id;
    if (!isValidObjectId(id)) return safeJson(res, 400, { error: "Invalid ID" });
    const emp = await Employee.findById(id);
    if (!emp) return safeJson(res, 404, { error: "Not found" });
    return safeJson(res, 200, emp);
  })
);

app.put(
  "/api/employees/:id",
  authMiddleware,
  requireRole(["admin", "manager"]),
  asyncHandler(async (req, res) => {
    const id = req.params.id;
    if (!isValidObjectId(id)) return safeJson(res, 400, { error: "Invalid ID" });
    const emp = await Employee.findByIdAndUpdate(id, req.body, { new: true });
    if (!emp) return safeJson(res, 404, { error: "Not found" });
    return safeJson(res, 200, emp);
  })
);

app.delete(
  "/api/employees/:id",
  authMiddleware,
  requireRole(["admin"]),
  asyncHandler(async (req, res) => {
    const id = req.params.id;
    if (!isValidObjectId(id)) return safeJson(res, 400, { error: "Invalid ID" });
    await Employee.findByIdAndDelete(id);
    return res.status(204).send();
  })
);


app.post(
  "/api/time/clockin",
  authMiddleware,
  requireRole(["admin", "manager", "employee"]),
  asyncHandler(async (req, res) => {
    const { employeeId, note, source } = req.body;
    if (!employeeId || !isValidObjectId(employeeId))
      return safeJson(res, 400, { error: "Invalid employeeId" });

    const emp = await Employee.findById(employeeId);
    if (!emp) return safeJson(res, 404, { error: "Employee not found" });

    const open = await TimeEntry.findOne({
      employee: employeeId,
      clockOut: { $exists: false },
    });

    if (open) return safeJson(res, 409, { error: "Already clocked in", entry: open });

    const entry = await TimeEntry.create({
      employee: employeeId,
      clockIn: nowUTC(),
      note,
      source: source || "web",
    });

    return safeJson(res, 201, entry);
  })
);

app.post(
  "/api/time/clockout",
  authMiddleware,
  requireRole(["admin", "manager", "employee"]),
  asyncHandler(async (req, res) => {
    const { employeeId, entryId } = req.body;
    let entry = null;

    if (entryId) {
      entry = await TimeEntry.findById(entryId);
      if (!entry) return safeJson(res, 404, { error: "Entry not found" });
      if (entry.clockOut)
        return safeJson(res, 409, { error: "Already clocked out" });
    } else {
      entry = await TimeEntry.findOne({
        employee: employeeId,
        clockOut: { $exists: false },
      }).sort({ clockIn: -1 });
      if (!entry) return safeJson(res, 404, { error: "No open entry found" });
    }

    const out = nowUTC();
    entry.clockOut = out;
    entry.durationMinutes = minutesBetween(entry.clockIn, out);
    await entry.save();

    return safeJson(res, 200, entry);
  })
);

app.get(
  "/api/time/entries",
  authMiddleware,
  asyncHandler(async (req, res) => {
    const { page, limit, skip } = parsePagination(req);
    const { employeeId, from, to } = req.query;

    const filter = {};
    if (employeeId) filter.employee = employeeId;
    if (from || to) filter.createdAt = {};
    if (from) filter.createdAt.$gte = new Date(from);
    if (to) filter.createdAt.$lte = new Date(to);

    const docs = await TimeEntry.find(filter)
      .populate("employee")
      .skip(skip)
      .limit(limit)
      .sort({ createdAt: -1 });

    const total = await TimeEntry.countDocuments(filter);

    return safeJson(res, 200, { total, page, limit, docs });
  })
);

app.get(
  "/api/time/export/csv",
  authMiddleware,
  requireRole(["admin", "manager"]),
  asyncHandler(async (req, res) => {
    const { employeeId, from, to } = req.query;
    const filter = {};
    if (employeeId) filter.employee = employeeId;
    if (from || to) filter.createdAt = {};
    if (from) filter.createdAt.$gte = new Date(from);
    if (to) filter.createdAt.$lte = new Date(to);

    const docs = await TimeEntry.find(filter)
      .populate("employee")
      .sort({ createdAt: -1 });

    const rows = docs.map((d) => ({
      id: d._id.toString(),
      employee: d.employee?.name,
      clockIn: toISONoMs(d.clockIn),
      clockOut: d.clockOut ? toISONoMs(d.clockOut) : "",
      durationMinutes: d.durationMinutes,
      note: d.note || "",
      source: d.source || "",
    }));

    const csv = stringify(rows, { header: true });

    res.setHeader("Content-disposition", "attachment; filename=timesheet.csv");
    res.set("Content-Type", "text/csv");
    res.send(csv);
  })
);

// --------------------
// Summary Route
// --------------------
app.get(
  "/api/time/summary",
  authMiddleware,
  requireRole(["admin", "manager"]),
  asyncHandler(async (req, res) => {
    const { from, to } = req.query;
    const match = {};
    if (from || to) match.createdAt = {};
    if (from) match.createdAt.$gte = new Date(from);
    if (to) match.createdAt.$lte = new Date(to);

    const summary = await TimeEntry.aggregate([
      { $match: match },
      { $group: { _id: "$employee", totalMinutes: { $sum: "$durationMinutes" }, count: { $sum: 1 } } },
      { $lookup: { from: "employees", localField: "_id", foreignField: "_id", as: "emp" } },
      { $unwind: "$emp" },
      { $project: { employeeId: "$_id", name: "$emp.name", totalMinutes: 1, count: 1 } },
      { $sort: { totalMinutes: -1 } },
    ]);

    return safeJson(res, 200, summary);
  })
);

app.get("/api/health", (req, res) => safeJson(res, 200, { status: "ok", time: nowUTC() }));

app.post(
  "/api/_seed/sample",
  asyncHandler(async (req, res) => {
    const names = ["Aman Mishra", "Neha Sharma", "Rohit Verma", "Priya Singh", "Karan Patel"];
    for (const n of names) {
      const exists = await Employee.findOne({ name: n });
      if (!exists)
        await Employee.create({ name: n, department: "Engineering", position: "Developer" });
    }

    const employees = await Employee.find();
    const now = new Date();
    for (let d = 0; d < 7; d++) {
      for (const emp of employees) {
        const inDate = new Date(now.getTime() - d * 24 * 60 * 60 * 1000 - Math.random() * 3 * 3600000);
        const outDate = new Date(inDate.getTime() + (7 + Math.floor(Math.random() * 3)) * 3600000 + Math.floor(Math.random() * 60) * 60000);
        await TimeEntry.create({ employee: emp._id, clockIn: inDate, clockOut: outDate, durationMinutes: minutesBetween(inDate, outDate), note: "seed" });
      }
    }

    safeJson(res, 201, { status: "seed complete" });
  })
);

app.use("/api", (req, res) => {
  res.status(404).json({ error: "Endpoint not found" });
});


app.use((err, req, res, next) => {
  console.error("Unhandled error:", err);
  safeJson(res, 500, { error: err.message });
});

mongoose
  .connect(MONGO_URI)
  .then(async () => {
    console.log("Connected to MongoDB");
    await createAdminIfMissing();
    app.listen(APP_PORT, () => console.log(`Server running at http://localhost:${APP_PORT}`));
  })
  .catch((err) => {
    console.error("MongoDB Error:", err);
    process.exit(1);
  });

