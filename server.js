require("dotenv").config();
const express = require("express");
const session = require("express-session");
const bcrypt = require("bcryptjs");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const nodemailer = require("nodemailer");

const app = express();
const PORT = 3000;

const DB_FILE = path.join(__dirname, "users.json");

// =========================
// DATABASE JSON
// =========================

function loadUsers() {
  try {
    if (!fs.existsSync(DB_FILE)) {
      fs.writeFileSync(DB_FILE, "[]");
    }

    return JSON.parse(fs.readFileSync(DB_FILE, "utf8"));
  } catch (error) {
    console.error("Gagal membaca database:", error);
    return [];
  }
}

function saveUsers(users) {
  fs.writeFileSync(DB_FILE, JSON.stringify(users, null, 2));
}

// =========================
// MIDDLEWARE
// =========================

app.use(express.urlencoded({ extended: true }));
app.use(express.json());

app.use(
  session({
    secret: "tokoweb-secret-2026",
    resave: false,
    saveUninitialized: false,
    cookie: {
      maxAge: 1000 * 60 * 60 * 24
    }
  })
);

app.use(express.static(path.join(__dirname, "public")));

// =========================
// HALAMAN AWAL
// =========================

app.get("/", (req, res) => {
  if (req.session.user) {
    return res.redirect("/dashboard.html");
  }

  res.redirect("/login.html");
});

// =========================
// PENDAFTARAN
// =========================

app.post("/register", async (req, res) => {
  try {
    const username = String(req.body.username || "").trim();
    const email = String(req.body.email || "").trim().toLowerCase();
    const password = String(req.body.password || "");

    // Validasi username
    if (!username) {
      return res.status(400).json({
        ok: false,
        message: "Username wajib diisi."
      });
    }

    if (username.length < 3) {
      return res.status(400).json({
        ok: false,
        message: "Username minimal 3 karakter."
      });
    }

    // Validasi email
    const emailValid =
      /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);

    if (!emailValid) {
      return res.status(400).json({
        ok: false,
        message: "Format email tidak valid."
      });
    }

    // Validasi password
    if (password.length < 6) {
      return res.status(400).json({
        ok: false,
        message: "Password minimal 6 karakter."
      });
    }

    const users = loadUsers();

    // Cek username
    const usernameExists = users.some(
      user => user.username.toLowerCase() === username.toLowerCase()
    );

    if (usernameExists) {
      return res.status(409).json({
        ok: false,
        message: "Username sudah digunakan."
      });
    }

    // Cek email
    const emailExists = users.some(
      user => user.email.toLowerCase() === email
    );

    if (emailExists) {
      return res.status(409).json({
        ok: false,
        message: "Email sudah terdaftar."
      });
    }

    // Hash password
    const passwordHash = await bcrypt.hash(password, 10);

    const newUser = {
      id: Date.now().toString(),
      username,
      email,
      password: passwordHash,
      createdAt: new Date().toISOString()
    };

    users.push(newUser);
    saveUsers(users);

    console.log("Akun baru:", username);

    // BERHASIL
    return res.json({
      ok: true,
      message: "Pendaftaran berhasil.",
      redirect: "/login.html?registered=1"
    });

  } catch (error) {
    console.error("REGISTER ERROR:", error);

    return res.status(500).json({
      ok: false,
      message: "Terjadi kesalahan pada server."
    });
  }
});

// =========================
// LOGIN
// =========================

app.post("/login", async (req, res) => {
  try {
    const username = String(req.body.username || "").trim();
    const password = String(req.body.password || "");
    const rememberMe = req.body.rememberMe === true;

    if (!username || !password) {
      return res.status(400).json({
        ok: false,
        message: "Username dan password wajib diisi."
      });
    }

    const users = loadUsers();

    const user = users.find(
      u => u.username.toLowerCase() === username.toLowerCase()
    );

    if (!user) {
      return res.status(401).json({
        ok: false,
        message: "Username atau password salah."
      });
    }

    const passwordCorrect = await bcrypt.compare(
      password,
      user.password
    );

    if (!passwordCorrect) {
      return res.status(401).json({
        ok: false,
        message: "Username atau password salah."
      });
    }

    req.session.user = {
      id: user.id,
      username: user.username,
      email: user.email
    };

    if (rememberMe) {
      req.session.cookie.maxAge = 30 * 24 * 60 * 60 * 1000;
    } else {
      req.session.cookie.expires = false;
      req.session.cookie.maxAge = null;
    }

    return res.json({
      ok: true,
      redirect: "/dashboard.html"
    });

  } catch (error) {
    console.error("LOGIN ERROR:", error);

    return res.status(500).json({
      ok: false,
      message: "Terjadi kesalahan pada server."
    });
  }
});

// =========================
// DATA USER LOGIN
// =========================

app.get("/api/me", (req, res) => {
  if (!req.session.user) {
    return res.status(401).json({
      ok: false,
      message: "Belum login."
    });
  }

  res.json({
    ok: true,
    user: req.session.user
  });
});

// =========================
// LOGOUT
// =========================

app.get("/logout", (req, res) => {
  req.session.destroy(() => {
    res.redirect("/login.html");
  });
});

// =========================
// SERVER
// =========================

app.listen(PORT, "0.0.0.0", () => {
  console.log("");
  console.log("==============================");
  console.log("        TOKO WEB AKTIF");
  console.log("==============================");
  console.log("");
  console.log("Buka Chrome:");
  console.log("http://localhost:3000");
  console.log("");
});

const transporter = {
  send: async (to, code) => {
    const apiKey = process.env.RESEND_API_KEY;

    const response = await fetch("https://api.resend.com/emails", {
      method: "POST",
      headers: {
        "Authorization": `Bearer ${apiKey}`,
        "Content-Type": "application/json"
      },
      body: JSON.stringify({
        from: "onboarding@resend.dev",
        to: [to],
        subject: "Kode Reset Password - Toko Web",
        html: `<h2>Reset Password</h2><p>Kode verifikasi kamu:</p><h1>${code}</h1><p>Kode berlaku selama 10 menit.</p>`
      })
    });

    if (!response.ok) {
      throw new Error(await response.text());
    }
  }
};


app.post("/forgot-password", async (req, res) => {
  try {
    const email = String(req.body.email || "").trim().toLowerCase();
    const users = loadUsers();
    const user = users.find(u => u.email.toLowerCase() === email);

    if (!user) {
      return res.status(404).json({
        ok: false,
        message: "Email belum terdaftar. Silakan daftar terlebih dahulu."
      });
    }

    const code = crypto.randomInt(100000, 1000000).toString();
    const codeHash = crypto
      .createHash("sha256")
      .update(code)
      .digest("hex");

    const resetData = {
      userId: user.id,
      codeHash,
      expiresAt: Date.now() + 10 * 60 * 1000,
      attempts: 0
    };

    fs.writeFileSync(
      path.join(__dirname, "reset-data.json"),
      JSON.stringify(resetData, null, 2)
    );

    await transporter.send(email, code);

    return res.json({
      ok: true,
      message: "Kode verifikasi telah dikirim ke email.",
      redirect: "/verify-code.html"
    });

  } catch (error) {
    console.error("FORGOT PASSWORD ERROR:", error.message);

    return res.status(500).json({
      ok: false,
      message: "Gagal mengirim kode. Coba lagi nanti."
    });
  }
});


app.post("/verify-reset-code", (req, res) => {
  try {
    const code = String(req.body.code || "").trim();

    if (!/^\d{6}$/.test(code)) {
      return res.status(400).json({
        ok: false,
        message: "Kode harus terdiri dari 6 angka."
      });
    }

    const resetFile = path.join(__dirname, "reset-data.json");

    if (!fs.existsSync(resetFile)) {
      return res.status(400).json({
        ok: false,
        message: "Kode tidak ditemukan atau sudah kedaluwarsa."
      });
    }

    const resetData = JSON.parse(fs.readFileSync(resetFile, "utf8"));

    if (!resetData.userId || !resetData.codeHash) {
      return res.status(400).json({
        ok: false,
        message: "Kode tidak valid."
      });
    }

    if (Date.now() > resetData.expiresAt) {
      return res.status(400).json({
        ok: false,
        message: "Kode sudah kedaluwarsa. Silakan minta kode baru."
      });
    }

    if ((resetData.attempts || 0) >= 5) {
      return res.status(429).json({
        ok: false,
        message: "Terlalu banyak percobaan. Silakan minta kode baru."
      });
    }

    resetData.attempts = (resetData.attempts || 0) + 1;

    const codeHash = crypto
      .createHash("sha256")
      .update(code)
      .digest("hex");

    if (codeHash !== resetData.codeHash) {
      fs.writeFileSync(resetFile, JSON.stringify(resetData, null, 2));

      return res.status(400).json({
        ok: false,
        message: "Kode salah."
      });
    }

    resetData.verified = true;
    resetData.resetToken = crypto.randomBytes(32).toString("hex");
    resetData.tokenExpiresAt = Date.now() + 10 * 60 * 1000;

    fs.writeFileSync(resetFile, JSON.stringify(resetData, null, 2));

    return res.json({
      ok: true,
      message: "Kode benar.",
      redirect: "/reset-password.html"
    });

  } catch (error) {
    console.error("VERIFY CODE ERROR:", error.message);

    return res.status(500).json({
      ok: false,
      message: "Terjadi kesalahan pada server."
    });
  }
});


app.post("/reset-password", async (req, res) => {
  try {
    const password = String(req.body.password || "");
    const resetFile = path.join(__dirname, "reset-data.json");

    if (password.length < 6) {
      return res.status(400).json({
        ok: false,
        message: "Password minimal 6 karakter."
      });
    }

    if (!fs.existsSync(resetFile)) {
      return res.status(400).json({
        ok: false,
        message: "Sesi reset tidak ditemukan."
      });
    }

    const resetData = JSON.parse(fs.readFileSync(resetFile, "utf8"));

    if (
      !resetData.verified ||
      !resetData.resetToken ||
      Date.now() > resetData.tokenExpiresAt
    ) {
      return res.status(400).json({
        ok: false,
        message: "Sesi reset sudah kedaluwarsa. Ulangi proses reset password."
      });
    }

    const users = loadUsers();
    const user = users.find(u => u.id === resetData.userId);

    if (!user) {
      return res.status(400).json({
        ok: false,
        message: "Akun tidak ditemukan."
      });
    }

    user.password = await bcrypt.hash(password, 10);
    saveUsers(users);

    fs.writeFileSync(resetFile, "[]");

    return res.json({
      ok: true,
      message: "Password berhasil diubah. Silakan login kembali."
    });

  } catch (error) {
    console.error("RESET PASSWORD ERROR:", error.message);

    return res.status(500).json({
      ok: false,
      message: "Gagal mengubah password."
    });
  }
});

