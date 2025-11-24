const express = require('express');
const path = require('path');
const crypto = require('crypto');          // untuk generate API key
const mysql = require('mysql2/promise');   // untuk koneksi MySQL
const bcrypt = require('bcryptjs');        // untuk hash password admin
const jwt = require('jsonwebtoken');       // untuk token admin

const app = express();
const PORT = 3000;

// ======= JWT CONFIG (sederhana dulu) =======
const JWT_SECRET = 'DEV_SECRET_PWS_123';   // sebaiknya nanti disimpan di .env
const JWT_EXPIRES_IN = '1h';               // token admin berlaku 1 jam

// Middleware untuk baca JSON body dari fetch() / Postman
app.use(express.json());

// Serve file statis dari folder "public"
app.use(express.static(path.join(__dirname, 'public')));

// =====================
// KONEKSI DATABASE
// =====================
const db = mysql.createPool({
  host: 'localhost',
  port: 3307,
  user: 'root',
  password: '1234567',
  database: 'praktikum7_pws',
});

async function testDbConnection() {
  try {
    const conn = await db.getConnection();
    await conn.ping();
    console.log('Koneksi ke MySQL berhasil');
    conn.release();
  } catch (err) {
    console.error('Gagal konek ke MySQL:', err);
  }
}

testDbConnection();

// =========================
// Helper: generate API key
// =========================
function generateApiKey(prefixRaw) {
  let prefix = '';

  if (prefixRaw && typeof prefixRaw === 'string') {
    prefix = prefixRaw.trim();
    if (prefix && !prefix.endsWith('_')) {
      prefix += '_'; // misal PWS_XXXX-XXXX-XXXX
    }
  }

  const segment = () => crypto.randomBytes(4).toString('hex').toUpperCase();
  const apiKey = `${prefix}${segment()}-${segment()}-${segment()}`;

  return apiKey;
}

// ===============================
//  MIDDLEWARE: cek token admin
//  (akan dipakai nanti untuk GET all users / api_keys)
// ===============================
function requireAdminAuth(req, res, next) {
  const authHeader = req.headers.authorization;

  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Token tidak ditemukan' });
  }

  const token = authHeader.split(' ')[1];

  try {
    const payload = jwt.verify(token, JWT_SECRET); // { adminId, email, iat, exp }
    req.admin = payload;
    next();
  } catch (err) {
    return res.status(401).json({ error: 'Token tidak valid atau sudah kadaluarsa' });
  }
}

// =======================
//  API: Generate API Key
//  (dipanggil dari front-end user)
// =======================
app.post('/api/generate-key', async (req, res) => {
  try {
    const {
      firstName,
      lastName,
      email,
      appName,
      description,
      expiry,
      scopes,
      prefix,
    } = req.body;

    if (!firstName || !lastName || !email) {
      return res.status(400).json({ error: 'firstName, lastName, dan email wajib diisi.' });
    }

    if (!appName || typeof appName !== 'string' || appName.trim() === '') {
      return res.status(400).json({ error: 'appName wajib diisi.' });
    }

    const finalScopes =
      Array.isArray(scopes) && scopes.length > 0 ? scopes : ['read'];

    // ===== 1. Cari atau buat user =====
    const [existing] = await db.execute(
      'SELECT id FROM users WHERE email = ? LIMIT 1',
      [email]
    );

    let userId;

    if (existing.length > 0) {
      userId = existing[0].id;
    } else {
      const [insertUser] = await db.execute(
        'INSERT INTO users (first_name, last_name, email, status) VALUES (?, ?, ?, ?)',
        [firstName, lastName, email, 'active']
      );
      userId = insertUser.insertId;
    }

    // ===== 2. Generate API key =====
    const apiKey = generateApiKey(prefix);

    // Hitung expires_at
    let expiresAt = null;
    if (expiry && expiry !== 'never') {
      const days = parseInt(expiry, 10);
      if (!Number.isNaN(days) && days > 0) {
        const now = new Date();
        now.setDate(now.getDate() + days);
        expiresAt = now; // object Date
      }
    }

    // ===== 3. Simpan ke tabel api_keys =====
    const [result] = await db.execute(
      'INSERT INTO api_keys (user_id, api_key, expires_at) VALUES (?, ?, ?)',
      [userId, apiKey, expiresAt]
    );

    const insertedId = result.insertId;

    return res.status(201).json({
      id: insertedId,
      userId,
      apiKey,
      appName,
      description: description || '',
      expiry,
      expiresAt,
      scopes: finalScopes,
      createdAt: new Date().toISOString(),
      message: 'API key berhasil dibuat dan disimpan ke database',
    });
  } catch (err) {
    console.error('Error /api/generate-key:', err);
    return res.status(500).json({ error: 'Internal server error' });
  }
});

// =============================
//  API: Validate API Key (POST)
// =============================
app.post('/api/validate-key', async (req, res) => {
  try {
    const { apiKey } = req.body;

    if (!apiKey || typeof apiKey !== 'string') {
      return res.status(400).json({ error: 'apiKey wajib diisi.' });
    }

    const [rows] = await db.execute(
      'SELECT id, user_id, api_key, created_at, expires_at FROM api_keys WHERE api_key = ? LIMIT 1',
      [apiKey]
    );

    if (rows.length === 0) {
      return res.status(404).json({
        valid: false,
        message: 'API key tidak ditemukan / tidak valid',
      });
    }

    const apiRow = rows[0];
    let status = 'active';

    if (apiRow.expires_at) {
      const now = new Date();
      const expires = new Date(apiRow.expires_at);
      if (expires < now) {
        status = 'inactive';
      }
    }

    return res.json({
      valid: status === 'active',
      status,
      id: apiRow.id,
      userId: apiRow.user_id,
      apiKey: apiRow.api_key,
      createdAt: apiRow.created_at,
      expiresAt: apiRow.expires_at,
      message:
        status === 'active'
          ? 'API key masih aktif'
          : 'API key sudah kadaluarsa / inactive',
    });
  } catch (err) {
    console.error('Error /api/validate-key:', err);
    return res.status(500).json({ error: 'Internal server error' });
  }
});


// =======================================
//  API: ADMIN REGISTER  (POST /api/admin/register)
// =======================================
app.post('/api/admin/register', async (req, res) => {
  try {
    const { email, password, confirmPassword } = req.body;

    if (!email || !password || !confirmPassword) {
      return res.status(400).json({ error: 'email, password, dan confirmPassword wajib diisi.' });
    }

    if (password.length < 6) {
      return res.status(400).json({ error: 'Password minimal 6 karakter.' });
    }

    if (password !== confirmPassword) {
      return res.status(400).json({ error: 'Konfirmasi password tidak cocok.' });
    }

    const passwordHash = await bcrypt.hash(password, 10);

    try {
      const [result] = await db.execute(
        'INSERT INTO admins (email, password_hash) VALUES (?, ?)',
        [email, passwordHash]
      );

      return res.status(201).json({
        id: result.insertId,
        email,
        message: 'Admin berhasil didaftarkan.',
      });
    } catch (err) {
      // cek kalau email sudah dipakai
      if (err.code === 'ER_DUP_ENTRY') {
        return res.status(409).json({ error: 'Email admin sudah terdaftar.' });
      }
      throw err;
    }
  } catch (err) {
    console.error('Error /api/admin/register:', err);
    return res.status(500).json({ error: 'Internal server error' });
  }
});

// =======================================
//  API: ADMIN LOGIN  (POST /api/admin/login)
// =======================================
app.post('/api/admin/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ error: 'email dan password wajib diisi.' });
    }

    const [rows] = await db.execute(
      'SELECT id, email, password_hash FROM admins WHERE email = ? LIMIT 1',
      [email]
    );

    if (rows.length === 0) {
      return res.status(401).json({ error: 'Email atau password salah.' });
    }

    const admin = rows[0];

    const passwordMatch = await bcrypt.compare(password, admin.password_hash);
    if (!passwordMatch) {
      return res.status(401).json({ error: 'Email atau password salah.' });
    }

    // Buat token
    const token = jwt.sign(
      { adminId: admin.id, email: admin.email },
      JWT_SECRET,
      { expiresIn: JWT_EXPIRES_IN }
    );

    return res.json({
      token,
      admin: {
        id: admin.id,
        email: admin.email,
      },
      message: 'Login berhasil.',
    });
  } catch (err) {
    console.error('Error /api/admin/login:', err);
    return res.status(500).json({ error: 'Internal server error' });
  }
});

// --- Middleware untuk proteksi endpoint admin ---
function authAdmin(req, res, next) {
  const authHeader = req.headers['authorization'] || '';
  const token = authHeader.startsWith('Bearer ')
    ? authHeader.slice(7)
    : null;

  if (!token) {
    return res.status(401).json({ error: 'Token admin diperlukan.' });
  }

  try {
    const payload = jwt.verify(token, JWT_SECRET);
    // Simpan info admin di request (bisa dipakai di handler)
    req.admin = { id: payload.id, email: payload.email };
    next();
  } catch (err) {
    console.error('Error verifikasi token admin:', err);
    return res
      .status(401)
      .json({ error: 'Token admin tidak valid atau sudah kedaluwarsa.' });
  }
}

// =============================
// GET /api/admin/users (protected)
// Mengembalikan list user + jumlah key dan key aktif
// =============================
app.get('/api/admin/users', authAdmin, async (req, res) => {
  try {
    const [rows] = await db.execute(
      `
      SELECT
        u.id,
        u.first_name,
        u.last_name,
        u.email,
        u.status,
        u.created_at,
        COUNT(k.id) AS total_keys,
        SUM(
          CASE
            WHEN k.expires_at IS NULL THEN 1
            WHEN k.expires_at > NOW() THEN 1
            ELSE 0
          END
        ) AS active_keys
      FROM users u
      LEFT JOIN api_keys k ON k.user_id = u.id
      GROUP BY
        u.id, u.first_name, u.last_name, u.email, u.status, u.created_at
      ORDER BY u.created_at DESC
      `
    );

    return res.json({ users: rows });
  } catch (err) {
    console.error('Error GET /api/admin/users:', err);
    return res.status(500).json({ error: 'Internal server error' });
  }
});

// =============================
// GET /api/admin/api-keys (protected)
// Mengembalikan list api keys + info user + status active/inactive
// =============================
app.get('/api/admin/api-keys', authAdmin, async (req, res) => {
  try {
    const [rows] = await db.execute(
      `
      SELECT
        k.id,
        k.api_key,
        k.created_at,
        k.expires_at,
        u.id AS user_id,
        u.first_name,
        u.last_name,
        u.email,
        CASE
          WHEN k.expires_at IS NULL THEN 'active'
          WHEN k.expires_at > NOW() THEN 'active'
          ELSE 'inactive'
        END AS status
      FROM api_keys k
      LEFT JOIN users u ON k.user_id = u.id
      ORDER BY k.created_at DESC
      `
    );

    return res.json({ apiKeys: rows });
  } catch (err) {
    console.error('Error GET /api/admin/api-keys:', err);
    return res.status(500).json({ error: 'Internal server error' });
  }
});

// =============================
//  API: History API key per user (by email)
//  GET /api/user/history?email=...
// =============================
app.get('/api/user/history', async (req, res) => {
  try {
    const { email } = req.query;

    if (!email || typeof email !== 'string' || email.trim() === '') {
      return res.status(400).json({ error: 'email wajib diisi.' });
    }

    const [rows] = await db.execute(
      `
      SELECT 
        ak.id,
        ak.api_key,
        ak.created_at,
        ak.expires_at,
        u.first_name,
        u.last_name,
        u.email
      FROM api_keys ak
      JOIN users u ON ak.user_id = u.id
      WHERE u.email = ?
      ORDER BY ak.created_at DESC
      `,
      [email.trim()]
    );

    const now = new Date();

    const apiKeys = rows.map((row) => {
      let status = 'active';
      if (row.expires_at && new Date(row.expires_at) <= now) {
        status = 'inactive';
      }

      return {
        id: row.id,
        api_key: row.api_key,
        created_at: row.created_at,
        expires_at: row.expires_at,
        status,
      };
    });

    return res.json({ apiKeys });
  } catch (err) {
    console.error('Error /api/user/history:', err);
    return res.status(500).json({ error: 'Internal server error' });
  }
});

// Start server
app.listen(PORT, () => {
  console.log(`App berjalan di http://localhost:${PORT}`);
});
