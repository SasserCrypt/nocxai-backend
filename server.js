// ===============================
// NoCxAI Backend – FINAL w/ Admin + SMTP Reset
// ===============================

import express from "express";
import cors from "cors";
import dotenv from "dotenv";
import mongoose from "mongoose";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import multer from "multer";
import path from "path";
import { fileURLToPath } from "url";
import fs from "fs";
import nodemailer from "nodemailer";
import crypto from "crypto";

dotenv.config();

// PATH FIX
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// EXPRESS
const app = express();
app.use(express.json());

// CORS
app.use(
  cors({
    origin: [
      "https://nocxai.com",
      "https://www.nocxai.com",
      "https://aptiq.nocxai.com",
      "http://localhost:5500",
      "http://localhost:3000"
    ],
    credentials: true
  })
);

// STATIC UPLOADS
const uploadsDir = path.join(__dirname, "uploads", "avatars");
fs.mkdirSync(uploadsDir, { recursive: true });
app.use("/uploads", express.static(path.join(__dirname, "uploads")));

// MONGO
mongoose
  .connect(process.env.MONGO_URI, { dbName: "nocxai" })
  .then(() => console.log("✅ MongoDB verbunden"))
  .catch(err => console.error("❌ MongoDB Fehler:", err));

// MODELS
const userSchema = new mongoose.Schema(
  {
    email: { type: String, required: true, unique: true, lowercase: true },
    passwordHash: { type: String, required: true },
    name: { type: String, default: "" },
    avatarUrl: { type: String, default: "" },
    role: { type: String, default: "user" }, // user | pro | ultimate | admin
    resetToken: { type: String, default: "" },
    resetTokenExpire: { type: Date, default: null }
  },
  { timestamps: true }
);
const User = mongoose.model("User", userSchema);

const logSchema = new mongoose.Schema(
  {
    type: String,
    message: String,
    userId: String,
    ip: String
  },
  { timestamps: true }
);
const Log = mongoose.model("Log", logSchema);

// HELPERS
function writeLog({ type, message, userId, ip }) {
  try {
    return Log.create({
      type,
      message,
      userId: userId || "",
      ip: ip || ""
    });
  } catch (e) {
    console.error("Log Fehler:", e.message);
  }
}

// AUTH MIDDLEWARE
function authRequired(req, res, next) {
  const auth = req.headers.authorization;
  if (!auth)
    return res.status(401).json({ success: false, message: "Kein Token" });

  try {
    const token = auth.replace("Bearer ", "").trim();
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded; // { id, email, role }
    next();
  } catch (err) {
    return res
      .status(401)
      .json({ success: false, message: "Token ungültig oder abgelaufen." });
  }
}

function adminOnly(req, res, next) {
  if (!req.user || req.user.role !== "admin")
    return res
      .status(403)
      .json({ success: false, message: "Admin Rechte erforderlich." });
  next();
}

// SMTP / Nodemailer
const transporter = nodemailer.createTransport({
  host: process.env.SMTP_HOST,
  port: Number(process.env.SMTP_PORT || 465),
  secure: process.env.SMTP_SECURE === "true",
  auth: {
    user: process.env.SMTP_USER,
    pass: process.env.SMTP_PASS
  }
});

// ROUTES

// REGISTER
app.post("/api/auth/register", async (req, res) => {
  try {
    const { email, password, name } = req.body;

    if (!email || !password)
      return res.status(400).json({
        success: false,
        message: "E-Mail und Passwort sind erforderlich."
      });

    const exists = await User.findOne({ email });
    if (exists)
      return res.status(409).json({
        success: false,
        message: "Diese E-Mail ist bereits vergeben."
      });

    const passwordHash = await bcrypt.hash(password, 10);

    const user = await User.create({
      email,
      passwordHash,
      name: name || "",
      role: "user"
    });

    await writeLog({
      type: "system",
      userId: user._id.toString(),
      message: `Neuer Benutzer registriert: ${email}`
    });

    res.json({ success: true, message: "Benutzer erfolgreich registriert." });
  } catch (err) {
    console.error("Register Fehler:", err);
    res.status(500).json({ success: false, message: "Serverfehler." });
  }
});

// LOGIN
app.post("/api/auth/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    const user = await User.findOne({ email });
    if (!user)
      return res
        .status(401)
        .json({ success: false, message: "Benutzer oder Passwort falsch." });

    const correct = await bcrypt.compare(password, user.passwordHash);
    if (!correct)
      return res
        .status(401)
        .json({ success: false, message: "Benutzer oder Passwort falsch." });

    const token = jwt.sign(
      { id: user._id.toString(), email: user.email, role: user.role },
      process.env.JWT_SECRET,
      { expiresIn: "7d" }
    );

    await writeLog({
      type: "login",
      userId: user._id.toString(),
      ip: req.ip,
      message: `Login erfolgreich: ${email}`
    });

    res.json({
      success: true,
      token,
      user: {
        id: user._id.toString(),
        email: user.email,
        name: user.name,
        avatarUrl: user.avatarUrl,
        role: user.role
      }
    });
  } catch (err) {
    console.error("Login Fehler:", err);
    res.status(500).json({ success: false, message: "Serverfehler." });
  }
});

// PASSWORD FORGOT (send mail)
app.post("/api/auth/forgot", async (req, res) => {
  try {
    const { email } = req.body;
    if (!email)
      return res
        .status(400)
        .json({ success: false, message: "E-Mail ist erforderlich." });

    const user = await User.findOne({ email });
    if (!user) {
      // Keine Info, ob User existiert -> Sicherheit
      return res.json({
        success: true,
        message: "Wenn die E-Mail existiert, wurde ein Reset-Link gesendet."
      });
    }

    const token = crypto.randomBytes(32).toString("hex");
    const expire = new Date(Date.now() + 1000 * 60 * 30); // 30 Minuten

    user.resetToken = token;
    user.resetTokenExpire = expire;
    await user.save();

    const resetUrl = `${process.env.BASE_URL.replace(/\/$/, "")}/reset.html?token=${token}`;

    const html = `
      <div style="font-family:system-ui, -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;background:#020617;padding:32px;color:#e5e7eb;">
        <div style="max-width:520px;margin:0 auto;background:radial-gradient(circle at top left,#1f2937,#020617);border-radius:18px;padding:24px 28px;border:1px solid rgba(148,163,184,0.4);">
          <h1 style="margin:0 0 12px;font-size:22px;color:#e5e7eb;">
            NoCxAI – Passwort zurücksetzen
          </h1>
          <p style="margin:0 0 16px;font-size:14px;color:#cbd5f5;">
            Hallo ${user.name || "NoCxAI User"},
          </p>
          <p style="margin:0 0 16px;font-size:14px;line-height:1.5;color:#cbd5f5;">
            Du hast angefragt, dein Passwort für dein NoCxAI-Konto zurückzusetzen.
            Klicke auf den Button, um ein neues Passwort zu vergeben. Dieser Link ist
            <strong>30 Minuten</strong> gültig.
          </p>
          <p style="text-align:center;margin:24px 0;">
            <a href="${resetUrl}" style="display:inline-block;background:linear-gradient(135deg,#8b5cf6,#06b6d4);color:white;text-decoration:none;padding:10px 24px;border-radius:999px;font-size:14px;">
              Passwort jetzt zurücksetzen
            </a>
          </p>
          <p style="margin:0 0 8px;font-size:12px;color:#9ca3af;">
            Falls der Button nicht funktioniert, kopiere diesen Link in deinen Browser:
          </p>
          <p style="word-break:break-all;font-size:11px;color:#6b7280;">${resetUrl}</p>
          <hr style="border:none;border-top:1px solid rgba(31,41,55,0.9);margin:18px 0;" />
          <p style="margin:0;font-size:11px;color:#6b7280;">
            Wenn du diese Anfrage nicht gestellt hast, kannst du diese E-Mail ignorieren.
          </p>
        </div>
      </div>
    `;

    await transporter.sendMail({
      from: process.env.MAIL_FROM || "NoCxAI <noreply@nocxai.com>",
      to: email,
      subject: "NoCxAI – Passwort zurücksetzen",
      html
    });

    await writeLog({
      type: "system",
      userId: user._id.toString(),
      message: `Passwort-Reset-Mail gesendet an: ${email}`,
      ip: req.ip
    });

    res.json({
      success: true,
      message: "Reset-E-Mail wurde gesendet, wenn die Adresse existiert."
    });
  } catch (err) {
    console.error("Forgot Fehler:", err);
    res
      .status(500)
      .json({ success: false, message: "Serverfehler beim Passwort-Reset." });
  }
});

// PASSWORD RESET USING TOKEN
app.post("/api/auth/reset", async (req, res) => {
  try {
    const { token, password } = req.body;
    if (!token || !password)
      return res.status(400).json({
        success: false,
        message: "Token und neues Passwort sind erforderlich."
      });

    const user = await User.findOne({
      resetToken: token,
      resetTokenExpire: { $gt: new Date() }
    });

    if (!user)
      return res.status(400).json({
        success: false,
        message: "Token ungültig oder abgelaufen."
      });

    user.passwordHash = await bcrypt.hash(password, 10);
    user.resetToken = "";
    user.resetTokenExpire = null;
    await user.save();

    await writeLog({
      type: "system",
      userId: user._id.toString(),
      message: `Passwort per Reset-Link geändert: ${user.email}`
    });

    res.json({ success: true, message: "Passwort erfolgreich geändert." });
  } catch (err) {
    console.error("Reset Fehler:", err);
    res.status(500).json({ success: false, message: "Serverfehler." });
  }
});

// CURRENT USER
app.get("/api/user/me", authRequired, async (req, res) => {
  try {
    const user = await User.findById(req.user.id).lean();
    if (!user)
      return res
        .status(404)
        .json({ success: false, message: "Benutzer nicht gefunden." });

    res.json({
      success: true,
      user: {
        id: user._id.toString(),
        email: user.email,
        name: user.name,
        avatarUrl: user.avatarUrl,
        role: user.role
      }
    });
  } catch (err) {
    console.error("GET /me Fehler:", err);
    res.status(500).json({ success: false });
  }
});

// UPDATE PROFILE
app.put("/api/user/update", authRequired, async (req, res) => {
  try {
    const updates = {};
    if (req.body.name) updates.name = req.body.name;
    if (req.body.email) updates.email = req.body.email;

    const user = await User.findByIdAndUpdate(req.user.id, updates, {
      new: true
    }).lean();

    res.json({ success: true, user });
  } catch (err) {
    console.error("Profil Error:", err);
    res.status(500).json({ success: false });
  }
});

// UPDATE PASSWORD (mit aktuellem Passwort)
app.put("/api/user/password", authRequired, async (req, res) => {
  try {
    const { currentPassword, newPassword } = req.body;
    if (!newPassword)
      return res
        .status(400)
        .json({ success: false, message: "Neues Passwort fehlt." });

    const user = await User.findById(req.user.id);
    if (!user)
      return res
        .status(404)
        .json({ success: false, message: "Benutzer nicht gefunden." });

    if (currentPassword) {
      const correct = await bcrypt.compare(currentPassword, user.passwordHash);
      if (!correct)
        return res
          .status(401)
          .json({ success: false, message: "Altes Passwort ist falsch." });
    }

    user.passwordHash = await bcrypt.hash(newPassword, 10);
    await user.save();

    res.json({ success: true, message: "Passwort aktualisiert." });
  } catch (err) {
    console.error("Passwort Fehler:", err);
    res.status(500).json({ success: false });
  }
});

// AVATAR UPLOAD
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, uploadsDir),
  filename: (req, file, cb) =>
    cb(
      null,
      `${req.user.id}-${Date.now()}${path.extname(file.originalname) || ".png"}`
    )
});

const upload = multer({
  storage,
  limits: { fileSize: 2e6 },
  fileFilter: (req, file, cb) => {
    if (!["image/png", "image/jpeg", "image/jpg"].includes(file.mimetype))
      return cb(new Error("Nur PNG/JPG erlaubt"));
    cb(null, true);
  }
});

app.post(
  "/api/user/avatar",
  authRequired,
  upload.single("avatar"),
  async (req, res) => {
    try {
      const relative = `/uploads/avatars/${req.file.filename}`;
      const fullUrl = (process.env.BASE_URL || "").replace(/\/$/, "") + relative;

      const user = await User.findByIdAndUpdate(
        req.user.id,
        { avatarUrl: fullUrl },
        { new: true }
      ).lean();

      res.json({ success: true, avatarUrl: user.avatarUrl });
    } catch (err) {
      console.error("Avatar Fehler:", err);
      res.status(500).json({ success: false });
    }
  }
);

// ADMIN ROUTES
app.get("/api/admin/users", authRequired, adminOnly, async (req, res) => {
  const users = await User.find().sort({ createdAt: -1 }).lean();
  res.json({ success: true, users });
});

app.get("/api/admin/stats", authRequired, adminOnly, async (req, res) => {
  const total = await User.countDocuments();
  const admins = await User.countDocuments({ role: "admin" });
  const pros = await User.countDocuments({ role: "pro" });
  const ultimate = await User.countDocuments({ role: "ultimate" });
  const logsCount = await Log.countDocuments();

  res.json({
    success: true,
    stats: { total, admins, pros, ultimate, logsCount }
  });
});

app.get("/api/admin/logs", authRequired, adminOnly, async (req, res) => {
  const limit = Number(req.query.limit) || 50;
  const logs = await Log.find().sort({ createdAt: -1 }).limit(limit).lean();
  res.json({ success: true, logs });
});

app.put("/api/admin/users/role", authRequired, adminOnly, async (req, res) => {
  const { userId, role } = req.body;
  const valid = ["user", "pro", "ultimate", "admin"];
  if (!valid.includes(role))
    return res
      .status(400)
      .json({ success: false, message: "Ungültige Rolle." });

  const updated = await User.findByIdAndUpdate(
    userId,
    { role },
    { new: true }
  ).lean();

  await writeLog({
    type: "admin",
    userId: userId,
    ip: req.ip,
    message: `Rolle geändert: ${updated?.email || userId} -> ${role}`
  });

  res.json({ success: true, user: updated });
});

app.delete(
  "/api/admin/users/delete/:id",
  authRequired,
  adminOnly,
  async (req, res) => {
    await User.findByIdAndDelete(req.params.id);
    await writeLog({
      type: "admin",
      userId: req.params.id,
      ip: req.ip,
      message: `Benutzer gelöscht: ${req.params.id}`
    });
    res.json({ success: true });
  }
);

app.delete(
  "/api/admin/users/avatar/:id",
  authRequired,
  adminOnly,
  async (req, res) => {
    const user = await User.findById(req.params.id);
    if (!user)
      return res
        .status(404)
        .json({ success: false, message: "Benutzer nicht gefunden." });

    if (user.avatarUrl) {
      const localFile = path.join(
        __dirname,
        user.avatarUrl.replace("/uploads/", "uploads/")
      );
      if (fs.existsSync(localFile)) fs.unlinkSync(localFile);
    }
    user.avatarUrl = "";
    await user.save();

    await writeLog({
      type: "admin",
      userId: req.params.id,
      ip: req.ip,
      message: `Avatar zurückgesetzt: ${user.email}`
    });

    res.json({ success: true });
  }
);

// START
const port = process.env.PORT || 4000;
app.listen(port, () => console.log(`🚀 NoCxAI Backend läuft auf Port ${port}`));
