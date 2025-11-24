// index.js
const express = require('express');
const path = require('path');
const crypto = require('crypto');          // untuk generate API key
const mysql = require('mysql2/promise');   // untuk koneksi MySQL

const app = express();
const PORT = 3000;

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
  user: 'root',               // ganti sesuai user MySQL kamu
  password: '1234567',        // ganti password MySQL kamu
  database: 'praktikum7_pws', // ganti sesuai nama DB yang kamu pakai
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

function addDays(date, days) {
  const result = new Date(date);
  result.setDate(result.getDate() + days);
  return result;
}

function toMySQLDateTime(date) {
  return date.toISOString().slice(0, 19).replace("T", " ");
}

// =======================
//  API: Generate API Key
//  (dipanggil dari front-end)
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
      prefix
    } = req.body;

    // ===== VALIDASI SEDERHANA =====
    if (!firstName || !lastName || !email || !appName) {
      return res.status(400).json({
        error: 'firstName, lastName, email, dan appName wajib diisi.'
      });
    }

    const finalScopes =
      Array.isArray(scopes) && scopes.length > 0 ? scopes : ['read'];

    // ===== 1. CARI / BUAT USER BERDASARKAN EMAIL =====
    let userId;
    let userRow;

    const [existing] = await db.execute(
      'SELECT id, first_name, last_name, email, status FROM users WHERE email = ? LIMIT 1',
      [email]
    );

    if (existing.length > 0) {
      // user sudah ada
      userRow = existing[0];
      userId = userRow.id;

      // Optional: update nama kalau berubah
      if (
        userRow.first_name !== firstName ||
        userRow.last_name !== lastName
      ) {
        await db.execute(
          'UPDATE users SET first_name = ?, last_name = ? WHERE id = ?',
          [firstName, lastName, userId]
        );
      }
    } else {
      // user baru
      const [insertUser] = await db.execute(
        'INSERT INTO users (first_name, last_name, email, status) VALUES (?, ?, ?, ?)',
        [firstName, lastName, email, 'active']
      );
      userId = insertUser.insertId;
      userRow = {
        id: userId,
        first_name: firstName,
        last_name: lastName,
        email,
        status: 'active'
      };
    }

    // ===== 2. HITUNG expires_at =====
    let expiresAt = null;
    if (expiry && expiry !== 'never') {
      const days = parseInt(expiry, 10);
      if (!Number.isNaN(days) && days > 0) {
        const now = new Date();
        expiresAt = addDays(now, days);
      }
    }

    const expiresAtStr = expiresAt ? toMySQLDateTime(expiresAt) : null;

    // ===== 3. GENERATE API KEY =====
    const apiKey = generateApiKey(prefix);

    // ===== 4. SIMPAN KE TABEL api_keys =====
    const [result] = await db.execute(
      'INSERT INTO api_keys (user_id, api_key, expires_at) VALUES (?, ?, ?)',
      [userId, apiKey, expiresAtStr]
    );

    const insertedId = result.insertId;

    // Hitung status key saat ini
    let keyStatus = 'active';
    if (expiresAt && expiresAt.getTime() < Date.now()) {
      keyStatus = 'inactive';
    }

    // ===== 5. RESPONSE KE FRONTEND =====
    return res.status(201).json({
      id: insertedId,
      apiKey,
      appName,
      description: description || '',
      expiry,                 // "1", "7", "30", "90", atau "never"
      scopes: finalScopes,
      createdAt: new Date().toISOString(),
      expiresAt: expiresAtStr,
      status: keyStatus,
      user: {
        id: userRow.id,
        fullName: `${firstName} ${lastName}`,
        email,
        status: userRow.status
      },
      message: 'API key berhasil dibuat, user terhubung, dan disimpan ke database'
    });
  } catch (err) {
    console.error('Error /api/generate-key:', err);
    return res.status(500).json({ error: 'Internal server error' });
  }
});


// =============================
//  API: Validate API Key (POST)
//  body: { "apiKey": "..." }
//  (dipakai di Postman)
// =============================
app.post('/api/validate-key', async (req, res) => {
  try {
    const { apiKey } = req.body;

    if (!apiKey || typeof apiKey !== 'string') {
      return res.status(400).json({ error: 'apiKey wajib diisi.' });
    }

    // Cek apakah apiKey ada di tabel
    const [rows] = await db.execute(
      'SELECT id, api_key, created_at FROM api_keys WHERE api_key = ? LIMIT 1',
      [apiKey]
    );

    if (rows.length === 0) {
      return res.status(404).json({
        valid: false,
        message: 'API key tidak ditemukan / tidak valid',
      });
    }

    return res.json({
      valid: true,
      id: rows[0].id,
      apiKey: rows[0].api_key,
      createdAt: rows[0].created_at,
      message: 'API key valid',
    });
  } catch (err) {
    console.error('Error /api/validate-key:', err);
    return res.status(500).json({ error: 'Internal server error' });
  }
});

// Start server
app.listen(PORT, () => {
  console.log(`App berjalan di http://localhost:${PORT}`);
});
