// server.js – NoCxAI Backend (Auth, Profil, Passwort, Avatar Upload) – Render/Atlas ready

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

dotenv.config();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();

// ==== CORS – passe hier deine Domains an ====
app.use(
  cors({
    origin: [
      "http://localhost:5500",
      "http://localhost:3000",
      "https://nocxai.com",
      "https://www.nocxai.com",
      "https://aptiq.nocxai.com"
    ],
    credentials: true,
  })
);

app.use(express.json());

// Static für Avatar-Bilder
const uploadsDir = path.join(__dirname, "uploads", "avatars");
fs.mkdirSync(uploadsDir, { recursive: true });
app.use("/uploads", express.static(path.join(__dirname, "uploads")));

// ==== MongoDB verbinden ====
mongoose
  .connect(process.env.MONGO_URI, {
    dbName: "nocxai",
  })
  .then(() => console.log("✅ MongoDB verbunden"))
  .catch((err) => console.error("❌ MongoDB Fehler:", err));

// ==== User Schema / Model ====
const userSchema = new mongoose.Schema(
  {
    email: { type: String, required: true, unique: true, lowercase: true },
    passwordHash: { type: String, required: true },
    name: { type: String, default: "" },
    avatarUrl: { type: String, default: "" },
    role: { type: String, default: "user" },
  },
  { timestamps: true }
);

const User = mongoose.model("User", userSchema);

// ==== JWT Middleware ====
function authRequired(req, res, next) {
  const auth = req.headers.authorization;
  if (!auth) {
    return res.status(401).json({ success: false, message: "Kein Token" });
  }

  const token = auth.replace("Bearer ", "").trim();
  try {
    const payload = jwt.verify(token, process.env.JWT_SECRET);
    req.user = payload; // { id, email, role }
    next();
  } catch (err) {
    return res.status(401).json({ success: false, message: "Ungültiger Token" });
  }
}

// ==== AUTH ROUTES ====

// Registrierung
app.post("/api/auth/register", async (req, res) => {
  try {
    const { email, password, name } = req.body;

    if (!email || !password) {
      return res
        .status(400)
        .json({ success: false, message: "E-Mail und Passwort sind erforderlich." });
    }

    const existing = await User.findOne({ email });
    if (existing) {
      return res
        .status(409)
        .json({ success: false, message: "Ein Benutzer mit dieser E-Mail existiert bereits." });
    }

    const passwordHash = await bcrypt.hash(password, 10);

    const user = await User.create({
      email,
      passwordHash,
      name: name || "",
      role: "user",
    });

    return res.json({ success: true, message: "Benutzer erstellt", userId: user._id });
  } catch (err) {
    console.error("Register Fehler:", err);
    res.status(500).json({ success: false, message: "Serverfehler bei Registrierung." });
  }
});

// Login
app.post("/api/auth/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res
        .status(400)
        .json({ success: false, message: "E-Mail und Passwort sind erforderlich." });
    }

    const user = await User.findOne({ email });
    if (!user) {
      return res
        .status(401)
        .json({ success: false, message: "Benutzer oder Passwort falsch." });
    }

    const ok = await bcrypt.compare(password, user.passwordHash);
    if (!ok) {
      return res
        .status(401)
        .json({ success: false, message: "Benutzer oder Passwort falsch." });
    }

    const token = jwt.sign(
      { id: user._id.toString(), email: user.email, role: user.role },
      process.env.JWT_SECRET,
      { expiresIn: "7d" }
    );

    return res.json({
      success: true,
      token,
      user: {
        id: user._id.toString(),
        email: user.email,
        name: user.name,
        avatarUrl: user.avatarUrl,
        role: user.role,
      },
    });
  } catch (err) {
    console.error("Login Fehler:", err);
    res.status(500).json({ success: false, message: "Serverfehler bei Login." });
  }
});

// ==== USER ROUTES (Profil, Passwort, Avatar) ====

// Aktuellen User holen
app.get("/api/user/me", authRequired, async (req, res) => {
  try {
    const user = await User.findById(req.user.id).lean();
    if (!user) {
      return res.status(404).json({ success: false, message: "Benutzer nicht gefunden." });
    }
    return res.json({
      success: true,
      user: {
        id: user._id.toString(),
        email: user.email,
        name: user.name,
        avatarUrl: user.avatarUrl,
        role: user.role,
      },
    });
  } catch (err) {
    console.error("GET /me Fehler:", err);
    res.status(500).json({ success: false, message: "Serverfehler." });
  }
});

// Profil aktualisieren (Name, Email)
app.put("/api/user/update", authRequired, async (req, res) => {
  try {
    const { name, email } = req.body;

    const updates = {};
    if (typeof name === "string") updates.name = name;
    if (typeof email === "string") updates.email = email;

    const user = await User.findByIdAndUpdate(req.user.id, updates, {
      new: true,
    }).lean();

    return res.json({
      success: true,
      message: "Profil aktualisiert.",
      user: {
        id: user._id.toString(),
        email: user.email,
        name: user.name,
        avatarUrl: user.avatarUrl,
        role: user.role,
      },
    });
  } catch (err) {
    console.error("Profil Update Fehler:", err);
    res.status(500).json({ success: false, message: "Serverfehler bei Profilupdate." });
  }
});

// Passwort ändern
app.put("/api/user/password", authRequired, async (req, res) => {
  try {
    const { currentPassword, newPassword } = req.body;

    if (!newPassword) {
      return res
        .status(400)
        .json({ success: false, message: "Neues Passwort fehlt." });
    }

    const user = await User.findById(req.user.id);
    if (!user) {
      return res.status(404).json({ success: false, message: "Benutzer nicht gefunden." });
    }

    // Optional: aktuelles Passwort prüfen (kannst du auch erzwingen)
    if (currentPassword) {
      const ok = await bcrypt.compare(currentPassword, user.passwordHash);
      if (!ok) {
        return res
          .status(401)
          .json({ success: false, message: "Altes Passwort ist falsch." });
      }
    }

    user.passwordHash = await bcrypt.hash(newPassword, 10);
    await user.save();

    return res.json({ success: true, message: "Passwort aktualisiert." });
  } catch (err) {
    console.error("Passwort ändern Fehler:", err);
    res.status(500).json({ success: false, message: "Serverfehler bei Passwortänderung." });
  }
});

// ==== AVATAR-UPLOAD mit Multer ====

const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, uploadsDir);
  },
  filename: function (req, file, cb) {
    const ext = path.extname(file.originalname) || ".png";
    const fileName = `${req.user.id}-${Date.now()}${ext}`;
    cb(null, fileName);
  },
});

const upload = multer({
  storage,
  limits: { fileSize: 2 * 1024 * 1024 }, // 2MB
  fileFilter: (req, file, cb) => {
    const ok = ["image/png", "image/jpeg", "image/jpg"].includes(file.mimetype);
    if (!ok) return cb(new Error("Nur PNG/JPG erlaubt"));
    cb(null, true);
  },
});

// Avatar-Upload
app.post(
  "/api/user/avatar",
  authRequired,
  upload.single("avatar"),
  async (req, res) => {
    try {
      const baseUrl = process.env.BASE_URL || "";
      const relativePath = `/uploads/avatars/${req.file.filename}`;
      const avatarUrl = baseUrl
        ? `${baseUrl}${relativePath}`
        : relativePath;

      const user = await User.findByIdAndUpdate(
        req.user.id,
        { avatarUrl },
        { new: true }
      ).lean();

      return res.json({
        success: true,
        message: "Avatar aktualisiert.",
        avatarUrl: user.avatarUrl,
      });
    } catch (err) {
      console.error("Avatar Upload Fehler:", err);
      res.status(500).json({ success: false, message: "Serverfehler bei Avatar-Upload." });
    }
  }
);

const port = process.env.PORT || 4000;
app.listen(port, () => {
  console.log(`🚀 NoCxAI Backend läuft auf Port ${port}`);
});
