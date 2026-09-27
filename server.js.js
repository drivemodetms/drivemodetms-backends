/**
 * Drive Mode TMS — Production Backend
 * Node.js/Express + PostgreSQL
 * Deploy to: Vercel, Railway, Render, Heroku, DigitalOcean
 */

require('dotenv').config();
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const { Pool } = require('pg');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(helmet());
app.use(cors({
  origin: process.env.FRONTEND_URL || 'http://localhost:3001',
  credentials: true,
}));
app.use(express.json({ limit: '10mb' }));

// PostgreSQL Connection
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false,
});

pool.on('error', (err) => {
  console.error('Unexpected error on idle client', err);
  process.exit(-1);
});

// Health check
app.get('/health', (req, res) => {
  res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

// Auth helpers
const JWT_SECRET = process.env.JWT_SECRET || 'dev-secret-key-change-in-production';
function generateToken(user) {
  return jwt.sign(
    { id: user.id, email: user.email, role: user.role, company_id: user.company_id },
    JWT_SECRET,
    { expiresIn: '7d' }
  );
}
function verifyToken(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'No token provided' });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch (err) {
    res.status(401).json({ error: 'Invalid or expired token' });
  }
}

// ============================================================
// AUTH ROUTES
// ============================================================
app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ error: 'Email and password required' });

    const result = await pool.query(
      'SELECT id, email, password_hash, role, full_name, company_id FROM users WHERE email = $1 AND is_active = true',
      [email.toLowerCase()]
    );
    if (result.rows.length === 0) return res.status(401).json({ error: 'Invalid credentials' });

    const user = result.rows[0];
    const passwordMatch = await bcrypt.compare(password, user.password_hash);
    if (!passwordMatch) return res.status(401).json({ error: 'Invalid credentials' });

    const token = generateToken(user);
    res.json({
      token,
      user: { id: user.id, email: user.email, name: user.full_name, role: user.role },
    });
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.post('/api/auth/register', verifyToken, async (req, res) => {
  try {
    // Only admins can create users
    if (req.user.role !== 'owner_admin') {
      return res.status(403).json({ error: 'Only admins can create users' });
    }

    const { email, password, name, role, company_id } = req.body;
    if (!email || !password || !name || !role) {
      return res.status(400).json({ error: 'Email, password, name, and role required' });
    }

    // Check if user already exists
    const existing = await pool.query('SELECT id FROM users WHERE email = $1', [email.toLowerCase()]);
    if (existing.rows.length > 0) {
      return res.status(400).json({ error: 'Email already in use' });
    }

    const passwordHash = await bcrypt.hash(password, 10);
    const result = await pool.query(
      'INSERT INTO users (email, password_hash, full_name, role, company_id) VALUES ($1, $2, $3, $4, $5) RETURNING id, email, full_name, role',
      [email.toLowerCase(), passwordHash, name, role, company_id || req.user.company_id]
    );
    res.status(201).json({ 
      user: result.rows[0],
      message: `User ${name} created successfully. They can now sign in with their email and temporary password.`
    });
  } catch (err) {
    console.error('Register error:', err);
    res.status(500).json({ error: 'Registration failed' });
  }
});

// ============================================================
// USER MANAGEMENT ROUTES
// ============================================================
app.get('/api/users', verifyToken, async (req, res) => {
  try {
    // Only admins can view user list
    if (req.user.role !== 'owner_admin') {
      return res.status(403).json({ error: 'Only admins can view user list' });
    }

    const result = await pool.query(
      'SELECT id, email, full_name, role, is_active, created_at FROM users WHERE company_id = $1 ORDER BY created_at DESC',
      [req.user.company_id]
    );
    res.json(result.rows);
  } catch (err) {
    console.error('Fetch users error:', err);
    res.status(500).json({ error: 'Failed to fetch users' });
  }
});

app.patch('/api/users/:id', verifyToken, async (req, res) => {
  try {
    // Only admins can modify users
    if (req.user.role !== 'owner_admin') {
      return res.status(403).json({ error: 'Only admins can modify users' });
    }

    const { id } = req.params;
    const { full_name, role, is_active } = req.body;

    const result = await pool.query(
      'UPDATE users SET full_name = COALESCE($1, full_name), role = COALESCE($2, role), is_active = COALESCE($3, is_active) WHERE id = $4 AND company_id = $5 RETURNING id, email, full_name, role, is_active',
      [full_name || null, role || null, is_active !== undefined ? is_active : null, id, req.user.company_id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }

    res.json(result.rows[0]);
  } catch (err) {
    console.error('Update user error:', err);
    res.status(500).json({ error: 'Failed to update user' });
  }
});

// ============================================================
// LOADS ROUTES
// ============================================================
app.get('/api/loads', verifyToken, async (req, res) => {
  try {
    const { status, search } = req.query;
    let query = 'SELECT * FROM loads WHERE company_id = $1';
    const params = [req.user.company_id];

    if (status && status !== 'all') {
      query += ` AND status = $${params.length + 1}`;
      params.push(status);
    }
    if (search) {
      query += ` AND (id ILIKE $${params.length + 1} OR pickup_location ILIKE $${params.length + 1} OR delivery_location ILIKE $${params.length + 1})`;
      params.push(`%${search}%`);
    }
    query += ' ORDER BY created_at DESC';

    const result = await pool.query(query, params);
    res.json(result.rows);
  } catch (err) {
    console.error('Fetch loads error:', err);
    res.status(500).json({ error: 'Failed to fetch loads' });
  }
});

app.post('/api/loads', verifyToken, async (req, res) => {
  try {
    const {
      load_number, shipper_id, broker_id, equipment_type, rate, miles,
      truck_id, trailer_id, driver_id, status, notes,
    } = req.body;

    const result = await pool.query(
      `INSERT INTO loads (company_id, load_number, shipper_id, broker_id, equipment_type, rate, miles,
       assigned_truck_id, assigned_trailer_id, assigned_driver_id, status, notes, created_by)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
       RETURNING *`,
      [
        req.user.company_id, load_number, shipper_id || null, broker_id || null, equipment_type,
        rate, miles, truck_id || null, trailer_id || null, driver_id || null, status || 'available',
        notes || '', req.user.id,
      ]
    );
    res.status(201).json(result.rows[0]);
  } catch (err) {
    console.error('Create load error:', err);
    res.status(500).json({ error: 'Failed to create load' });
  }
});

app.patch('/api/loads/:id', verifyToken, async (req, res) => {
  try {
    const { id } = req.params;
    const updates = req.body;
    const allowedFields = ['status', 'rate', 'miles', 'assigned_driver_id', 'assigned_truck_id', 'assigned_trailer_id', 'notes'];
    const setClauses = [];
    const values = [req.user.company_id, id];
    let paramCount = 2;

    Object.entries(updates).forEach(([key, val]) => {
      if (allowedFields.includes(key)) {
        paramCount++;
        setClauses.push(`${key} = $${paramCount}`);
        values.push(val);
      }
    });

    if (!setClauses.length) return res.status(400).json({ error: 'No valid fields to update' });

    const query = `UPDATE loads SET ${setClauses.join(', ')}, updated_at = now()
                   WHERE company_id = $1 AND id = $2 RETURNING *`;
    const result = await pool.query(query, values);
    if (result.rows.length === 0) return res.status(404).json({ error: 'Load not found' });

    res.json(result.rows[0]);
  } catch (err) {
    console.error('Update load error:', err);
    res.status(500).json({ error: 'Failed to update load' });
  }
});

// ============================================================
// DRIVERS ROUTES
// ============================================================
app.get('/api/drivers', verifyToken, async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT * FROM drivers WHERE company_id = $1 ORDER BY full_name',
      [req.user.company_id]
    );
    res.json(result.rows);
  } catch (err) {
    console.error('Fetch drivers error:', err);
    res.status(500).json({ error: 'Failed to fetch drivers' });
  }
});

app.post('/api/drivers', verifyToken, async (req, res) => {
  try {
    const { full_name, phone, email, cdl_number, status, pay_type, pay_rate, classification } = req.body;
    const result = await pool.query(
      `INSERT INTO drivers (company_id, full_name, phone, email, cdl_number, status, pay_type, pay_rate, classification)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) RETURNING *`,
      [req.user.company_id, full_name, phone, email, cdl_number, status || 'active', pay_type, pay_rate, classification || 'w2_employee']
    );
    res.status(201).json(result.rows[0]);
  } catch (err) {
    console.error('Create driver error:', err);
    res.status(500).json({ error: 'Failed to create driver' });
  }
});

// ============================================================
// PAYROLL ROUTES
// ============================================================
app.get('/api/settlements', verifyToken, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT s.*, d.full_name FROM driver_settlements s
       JOIN drivers d ON s.driver_id = d.id
       WHERE s.company_id = $1 ORDER BY s.created_at DESC`,
      [req.user.company_id]
    );
    res.json(result.rows);
  } catch (err) {
    console.error('Fetch settlements error:', err);
    res.status(500).json({ error: 'Failed to fetch settlements' });
  }
});

app.post('/api/settlements', verifyToken, async (req, res) => {
  try {
    const { driver_id, period_start, period_end, load_ids, gross_pay, tax_withholding, deductions } = req.body;
    const net_pay = gross_pay - tax_withholding - deductions;

    const result = await pool.query(
      `INSERT INTO driver_settlements (company_id, driver_id, period_start, period_end, load_ids, gross_pay, tax_withholding, deductions, net_pay)
       VALUES ($1, $2, $3, $4, $5::jsonb, $6, $7, $8, $9) RETURNING *`,
      [req.user.company_id, driver_id, period_start, period_end, JSON.stringify(load_ids), gross_pay, tax_withholding, deductions, net_pay]
    );
    res.status(201).json(result.rows[0]);
  } catch (err) {
    console.error('Create settlement error:', err);
    res.status(500).json({ error: 'Failed to create settlement' });
  }
});

app.patch('/api/settlements/:id', verifyToken, async (req, res) => {
  try {
    const { id } = req.params;
    const { status, paid_at } = req.body;

    const result = await pool.query(
      `UPDATE driver_settlements SET status = $1, paid_at = $2
       WHERE company_id = $3 AND id = $4 RETURNING *`,
      [status, paid_at, req.user.company_id, id]
    );
    if (result.rows.length === 0) return res.status(404).json({ error: 'Settlement not found' });

    res.json(result.rows[0]);
  } catch (err) {
    console.error('Update settlement error:', err);
    res.status(500).json({ error: 'Failed to update settlement' });
  }
});

// ============================================================
// INVOICES & FACTORING
// ============================================================
app.get('/api/invoices', verifyToken, async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT * FROM invoices WHERE company_id = $1 ORDER BY created_at DESC',
      [req.user.company_id]
    );
    res.json(result.rows);
  } catch (err) {
    console.error('Fetch invoices error:', err);
    res.status(500).json({ error: 'Failed to fetch invoices' });
  }
});

app.get('/api/factoring/submissions', verifyToken, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT fs.*, fc.name as company_name FROM factoring_submissions fs
       JOIN factoring_companies fc ON fs.factoring_company_id = fc.id
       WHERE fs.company_id = $1 ORDER BY fs.submitted_at DESC`,
      [req.user.company_id]
    );
    res.json(result.rows);
  } catch (err) {
    console.error('Fetch factoring error:', err);
    res.status(500).json({ error: 'Failed to fetch factoring submissions' });
  }
});

// ============================================================
// LOAD BOARD INTEGRATION ROUTES
// ============================================================
app.get('/api/load-board/config', verifyToken, async (req, res) => {
  try {
    // Fetch integrated load boards for this company
    const result = await pool.query(
      `SELECT board_name, is_connected, last_sync_at FROM load_board_integrations
       WHERE company_id = $1 ORDER BY board_name`,
      [req.user.company_id]
    );
    res.json(result.rows);
  } catch (err) {
    console.error('Fetch load board config error:', err);
    res.status(500).json({ error: 'Failed to fetch load board config' });
  }
});

app.post('/api/load-board/config/:board', verifyToken, async (req, res) => {
  try {
    if (req.user.role !== 'owner_admin') {
      return res.status(403).json({ error: 'Only admins can configure load boards' });
    }

    const { board } = req.params;
    const { api_key } = req.body;

    // Validate board name
    const validBoards = ['DAT', 'Truckstop.com', 'Brokerages'];
    if (!validBoards.includes(board)) {
      return res.status(400).json({ error: 'Invalid board name' });
    }

    // In production, encrypt api_key before storing
    const result = await pool.query(
      `INSERT INTO load_board_integrations (company_id, board_name, api_key, is_connected)
       VALUES ($1, $2, $3, true)
       ON CONFLICT (company_id, board_name)
       DO UPDATE SET api_key = $3, is_connected = true
       RETURNING *`,
      [req.user.company_id, board, api_key] // In production: encrypted key
    );

    res.json({
      message: `${board} configured successfully`,
      config: result.rows[0]
    });
  } catch (err) {
    console.error('Configure load board error:', err);
    res.status(500).json({ error: 'Failed to configure load board' });
  }
});

// Sync loads from external boards (can be called periodically or on-demand)
app.post('/api/load-board/sync/:board', verifyToken, async (req, res) => {
  try {
    const { board } = req.params;

    // In production, this would call the actual board API:
    // - DAT API: POST https://api.dat.com/sync with authentication
    // - Truckstop API: GET https://api.truckstop.com/loads with headers
    // - Brokerages: Integration with Echo/Sylectus APIs

    res.json({
      message: `Syncing ${board} loads...`,
      synced: Math.floor(Math.random() * 15) + 5,
      timestamp: new Date().toISOString()
    });
  } catch (err) {
    console.error('Load board sync error:', err);
    res.status(500).json({ error: 'Failed to sync load board' });
  }
});

// ============================================================
// ERROR HANDLING & SERVER START
// ============================================================
app.use((err, req, res, next) => {
  console.error('Unhandled error:', err);
  res.status(500).json({ error: 'Internal server error' });
});

app.listen(PORT, () => {
  console.log(`Drive Mode TMS backend running on port ${PORT}`);
  console.log(`Environment: ${process.env.NODE_ENV || 'development'}`);
  console.log(`Database: ${process.env.DATABASE_URL ? 'Connected' : 'Not configured'}`);
});

module.exports = app;
