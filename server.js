// server.js - Complete Backend API for Driver Tracking App
const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const { Pool } = require('pg');
const multer = require('multer');
require('dotenv').config();

const app = express();
const upload = multer({ dest: 'uploads/' });

// Database connection
const pool = new Pool({
  host: process.env.DB_HOST || 'localhost',
  port: process.env.DB_PORT || 5432,
  database: process.env.DB_NAME || 'driver_tracking',
  user: process.env.DB_USER || 'postgres',
  password: process.env.DB_PASSWORD
});

app.use(cors());
app.use(express.json());
app.use('/uploads', express.static('uploads'));

const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key-change-in-production';

// Health check endpoint
app.get('/health', (req, res) => {
  res.json({ status: 'ok', message: 'Server is running' });
});

// Middleware to verify JWT token
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) return res.status(401).json({ error: 'Access denied' });

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: 'Invalid token' });
    req.user = user;
    next();
  });
};

// Middleware to verify admin
const verifyAdmin = (req, res, next) => {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Admin access required' });
  }
  next();
};

// AUTH ROUTES
app.post('/api/auth/register', authenticateToken, verifyAdmin, async (req, res) => {
  try {
    const { email, password, firstName, lastName, phoneNumber } = req.body;
    
    const userExists = await pool.query('SELECT id FROM users WHERE email = $1', [email]);
    if (userExists.rows.length > 0) {
      return res.status(400).json({ error: 'User already exists' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const result = await pool.query(
      `INSERT INTO users (email, password, first_name, last_name, phone_number, role, status)
       VALUES ($1, $2, $3, $4, $5, 'driver', 'active')
       RETURNING id, email, first_name, last_name, role, status`,
      [email, hashedPassword, firstName, lastName, phoneNumber]
    );

    res.status(201).json({ user: result.rows[0] });
  } catch (error) {
    console.error('Registration error:', error);
    res.status(500).json({ error: 'Registration failed' });
  }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    const result = await pool.query('SELECT * FROM users WHERE email = $1', [email]);

    if (result.rows.length === 0) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const user = result.rows[0];

    if (user.status !== 'active') {
      return res.status(403).json({ error: 'Account is inactive' });
    }

    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const token = jwt.sign(
      { userId: user.id, email: user.email, role: user.role },
      JWT_SECRET,
      { expiresIn: '7d' }
    );

    res.json({
      token,
      user: {
        id: user.id,
        email: user.email,
        firstName: user.first_name,
        lastName: user.last_name,
        role: user.role
      }
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Login failed' });
  }
});

// SHIFT ROUTES
app.post('/api/shifts/start', authenticateToken, async (req, res) => {
  try {
    const { latitude, longitude } = req.body;

    const result = await pool.query(
      `INSERT INTO shifts (user_id, start_time, start_latitude, start_longitude, status)
       VALUES ($1, NOW(), $2, $3, 'active')
       RETURNING *`,
      [req.user.userId, latitude, longitude]
    );

    res.status(201).json({ shift: result.rows[0] });
  } catch (error) {
    console.error('Start shift error:', error);
    res.status(500).json({ error: 'Failed to start shift' });
  }
});

app.put('/api/shifts/:shiftId/end', authenticateToken, async (req, res) => {
  try {
    const { shiftId } = req.params;
    const { latitude, longitude, mileage } = req.body;

    const result = await pool.query(
      `UPDATE shifts 
       SET end_time = NOW(), end_latitude = $1, end_longitude = $2, 
           mileage = $3, status = 'completed'
       WHERE id = $4 AND user_id = $5 AND status = 'active'
       RETURNING *`,
      [latitude, longitude, mileage, shiftId, req.user.userId]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Active shift not found' });
    }

    res.json({ shift: result.rows[0] });
  } catch (error) {
    console.error('End shift error:', error);
    res.status(500).json({ error: 'Failed to end shift' });
  }
});

app.post('/api/shifts/:shiftId/locations', authenticateToken, async (req, res) => {
  try {
    const { shiftId } = req.params;
    const { latitude, longitude } = req.body;

    await pool.query(
      `INSERT INTO shift_locations (shift_id, latitude, longitude, recorded_at)
       VALUES ($1, $2, $3, NOW())`,
      [shiftId, latitude, longitude]
    );

    res.status(201).json({ message: 'Location tracked' });
  } catch (error) {
    console.error('Track location error:', error);
    res.status(500).json({ error: 'Failed to track location' });
  }
});

app.get('/api/shifts', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT * FROM shifts 
       WHERE user_id = $1 
       ORDER BY start_time DESC`,
      [req.user.userId]
    );

    res.json({ shifts: result.rows });
  } catch (error) {
    console.error('Get shifts error:', error);
    res.status(500).json({ error: 'Failed to fetch shifts' });
  }
});

app.get('/api/shifts/active', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT * FROM shifts 
       WHERE user_id = $1 AND status = 'active'
       ORDER BY start_time DESC LIMIT 1`,
      [req.user.userId]
    );

    res.json({ shift: result.rows[0] || null });
  } catch (error) {
    console.error('Get active shift error:', error);
    res.status(500).json({ error: 'Failed to fetch active shift' });
  }
});

// GAS REQUEST ROUTES
app.post('/api/gas-requests', authenticateToken, upload.single('receipt'), async (req, res) => {
  try {
    const { amount, station } = req.body;
    const receiptPath = req.file ? req.file.path : null;

    const result = await pool.query(
      `INSERT INTO gas_requests (user_id, amount, station, receipt_path, status)
       VALUES ($1, $2, $3, $4, 'pending')
       RETURNING *`,
      [req.user.userId, amount, station, receiptPath]
    );

    res.status(201).json({ gasRequest: result.rows[0] });
  } catch (error) {
    console.error('Submit gas request error:', error);
    res.status(500).json({ error: 'Failed to submit gas request' });
  }
});

app.get('/api/gas-requests', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT * FROM gas_requests 
       WHERE user_id = $1 
       ORDER BY created_at DESC`,
      [req.user.userId]
    );

    res.json({ gasRequests: result.rows });
  } catch (error) {
    console.error('Get gas requests error:', error);
    res.status(500).json({ error: 'Failed to fetch gas requests' });
  }
});

// ADMIN ROUTES
app.get('/api/admin/drivers', authenticateToken, verifyAdmin, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT id, email, first_name, last_name, phone_number, status, created_at
       FROM users 
       WHERE role = 'driver'
       ORDER BY created_at DESC`
    );

    res.json({ drivers: result.rows });
  } catch (error) {
    console.error('Get drivers error:', error);
    res.status(500).json({ error: 'Failed to fetch drivers' });
  }
});

app.get('/api/admin/shifts', authenticateToken, verifyAdmin, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT s.*, u.first_name, u.last_name, u.email
       FROM shifts s
       JOIN users u ON s.user_id = u.id
       ORDER BY s.start_time DESC`
    );

    res.json({ shifts: result.rows });
  } catch (error) {
    console.error('Get all shifts error:', error);
    res.status(500).json({ error: 'Failed to fetch shifts' });
  }
});

app.get('/api/admin/gas-requests', authenticateToken, verifyAdmin, async (req, res) => {
  try {
    const { status } = req.query;
    
    let query = `
      SELECT gr.*, u.first_name, u.last_name, u.email
      FROM gas_requests gr
      JOIN users u ON gr.user_id = u.id
    `;
    const params = [];
    
    if (status) {
      query += ' WHERE gr.status = $1';
      params.push(status);
    }
    
    query += ' ORDER BY gr.created_at DESC';

    const result = await pool.query(query, params);
    res.json({ gasRequests: result.rows });
  } catch (error) {
    console.error('Get gas requests error:', error);
    res.status(500).json({ error: 'Failed to fetch gas requests' });
  }
});

app.put('/api/admin/gas-requests/:requestId', authenticateToken, verifyAdmin, async (req, res) => {
  try {
    const { requestId } = req.params;
    const { status, notes } = req.body;

    if (!['approved', 'rejected'].includes(status)) {
      return res.status(400).json({ error: 'Invalid status' });
    }

    const result = await pool.query(
      `UPDATE gas_requests 
       SET status = $1, admin_notes = $2, reviewed_at = NOW(), reviewed_by = $3
       WHERE id = $4
       RETURNING *`,
      [status, notes, req.user.userId, requestId]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Gas request not found' });
    }

    res.json({ gasRequest: result.rows[0] });
  } catch (error) {
    console.error('Update gas request error:', error);
    res.status(500).json({ error: 'Failed to update gas request' });
  }
});

app.put('/api/admin/drivers/:driverId', authenticateToken, verifyAdmin, async (req, res) => {
  try {
    const { driverId } = req.params;
    const { status } = req.body;

    if (!['active', 'inactive', 'suspended'].includes(status)) {
      return res.status(400).json({ error: 'Invalid status' });
    }

    const result = await pool.query(
      `UPDATE users 
       SET status = $1
       WHERE id = $2 AND role = 'driver'
       RETURNING id, email, first_name, last_name, status`,
      [status, driverId]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Driver not found' });
    }

    res.json({ driver: result.rows[0] });
  } catch (error) {
    console.error('Update driver error:', error);
    res.status(500).json({ error: 'Failed to update driver' });
  }
});

app.get('/api/admin/stats', authenticateToken, verifyAdmin, async (req, res) => {
  try {
    const stats = await pool.query(`
      SELECT 
        (SELECT COUNT(*) FROM users WHERE role = 'driver' AND status = 'active') as active_drivers,
        (SELECT COUNT(*) FROM shifts WHERE status = 'active') as active_shifts,
        (SELECT COUNT(*) FROM gas_requests WHERE status = 'pending') as pending_gas_requests,
        (SELECT COALESCE(SUM(mileage), 0) FROM shifts WHERE DATE(start_time) = CURRENT_DATE) as today_mileage,
        (SELECT COALESCE(SUM(amount), 0) FROM gas_requests WHERE status = 'approved' AND DATE(created_at) = CURRENT_DATE) as today_gas_expenses
    `);

    res.json({ stats: stats.rows[0] });
  } catch (error) {
    console.error('Get stats error:', error);
    res.status(500).json({ error: 'Failed to fetch stats' });
  }
});

// DATABASE INITIALIZATION
const initDatabase = async () => {
  try {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        email VARCHAR(255) UNIQUE NOT NULL,
        password VARCHAR(255) NOT NULL,
        first_name VARCHAR(100),
        last_name VARCHAR(100),
        phone_number VARCHAR(20),
        role VARCHAR(20) DEFAULT 'driver',
        status VARCHAR(20) DEFAULT 'active',
        created_at TIMESTAMP DEFAULT NOW()
      );

      CREATE TABLE IF NOT EXISTS shifts (
        id SERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES users(id),
        start_time TIMESTAMP NOT NULL,
        end_time TIMESTAMP,
        start_latitude DECIMAL(10, 8),
        start_longitude DECIMAL(11, 8),
        end_latitude DECIMAL(10, 8),
        end_longitude DECIMAL(11, 8),
        mileage DECIMAL(10, 2),
        status VARCHAR(20) DEFAULT 'active',
        created_at TIMESTAMP DEFAULT NOW()
      );

      CREATE TABLE IF NOT EXISTS shift_locations (
        id SERIAL PRIMARY KEY,
        shift_id INTEGER REFERENCES shifts(id),
        latitude DECIMAL(10, 8),
        longitude DECIMAL(11, 8),
        recorded_at TIMESTAMP DEFAULT NOW()
      );

      CREATE TABLE IF NOT EXISTS gas_requests (
        id SERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES users(id),
        amount DECIMAL(10, 2) NOT NULL,
        station VARCHAR(255),
        receipt_path VARCHAR(500),
        status VARCHAR(20) DEFAULT 'pending',
        admin_notes TEXT,
        reviewed_by INTEGER REFERENCES users(id),
        reviewed_at TIMESTAMP,
        created_at TIMESTAMP DEFAULT NOW()
      );

      CREATE INDEX IF NOT EXISTS idx_shifts_user_id ON shifts(user_id);
      CREATE INDEX IF NOT EXISTS idx_gas_requests_user_id ON gas_requests(user_id);
      CREATE INDEX IF NOT EXISTS idx_gas_requests_status ON gas_requests(status);
    `);

    const adminExists = await pool.query('SELECT id FROM users WHERE email = $1', ['admin@example.com']);
    if (adminExists.rows.length === 0) {
      const hashedPassword = await bcrypt.hash('admin123', 10);
      await pool.query(
        `INSERT INTO users (email, password, first_name, last_name, role, status)
         VALUES ($1, $2, 'Admin', 'User', 'admin', 'active')`,
        ['admin@example.com', hashedPassword]
      );
      console.log('✅ Default admin created: admin@example.com / admin123');
    }

    console.log('✅ Database initialized successfully');
  } catch (error) {
    console.error('❌ Database initialization error:', error);
  }
};

const PORT = process.env.PORT || 3001;

app.listen(PORT, async () => {
  await initDatabase();
  console.log(`🚀 Server running on port ${PORT}`);
// server.js - Complete Backend API for Driver Tracking App
const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const { Pool } = require('pg');
const multer = require('multer');
require('dotenv').config();

const app = express();
const upload = multer({ dest: 'uploads/' });

// Database connection
const pool = new Pool({
  host: process.env.DB_HOST || 'localhost',
  port: process.env.DB_PORT || 5432,
  database: process.env.DB_NAME || 'driver_tracking',
  user: process.env.DB_USER || 'postgres',
  password: process.env.DB_PASSWORD
});

app.use(cors());
app.use(express.json());
app.use('/uploads', express.static('uploads'));

const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key-change-in-production';

// Health check endpoint
app.get('/health', (req, res) => {
  res.json({ status: 'ok', message: 'Server is running' });
});

// Middleware to verify JWT token
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) return res.status(401).json({ error: 'Access denied' });

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: 'Invalid token' });
    req.user = user;
    next();
  });
};

// Middleware to verify admin
const verifyAdmin = (req, res, next) => {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Admin access required' });
  }
  next();
};

// AUTH ROUTES
app.post('/api/auth/register', authenticateToken, verifyAdmin, async (req, res) => {
  try {
    const { email, password, firstName, lastName, phoneNumber } = req.body;
    
    const userExists = await pool.query('SELECT id FROM users WHERE email = $1', [email]);
    if (userExists.rows.length > 0) {
      return res.status(400).json({ error: 'User already exists' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const result = await pool.query(
      `INSERT INTO users (email, password, first_name, last_name, phone_number, role, status)
       VALUES ($1, $2, $3, $4, $5, 'driver', 'active')
       RETURNING id, email, first_name, last_name, role, status`,
      [email, hashedPassword, firstName, lastName, phoneNumber]
    );

    res.status(201).json({ user: result.rows[0] });
  } catch (error) {
    console.error('Registration error:', error);
    res.status(500).json({ error: 'Registration failed' });
  }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    const result = await pool.query('SELECT * FROM users WHERE email = $1', [email]);

    if (result.rows.length === 0) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const user = result.rows[0];

    if (user.status !== 'active') {
      return res.status(403).json({ error: 'Account is inactive' });
    }

    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const token = jwt.sign(
      { userId: user.id, email: user.email, role: user.role },
      JWT_SECRET,
      { expiresIn: '7d' }
    );

    res.json({
      token,
      user: {
        id: user.id,
        email: user.email,
        firstName: user.first_name,
        lastName: user.last_name,
        role: user.role
      }
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Login failed' });
  }
});

// SHIFT ROUTES
app.post('/api/shifts/start', authenticateToken, async (req, res) => {
  try {
    const { latitude, longitude } = req.body;

    const result = await pool.query(
      `INSERT INTO shifts (user_id, start_time, start_latitude, start_longitude, status)
       VALUES ($1, NOW(), $2, $3, 'active')
       RETURNING *`,
      [req.user.userId, latitude, longitude]
    );

    res.status(201).json({ shift: result.rows[0] });
  } catch (error) {
    console.error('Start shift error:', error);
    res.status(500).json({ error: 'Failed to start shift' });
  }
});

app.put('/api/shifts/:shiftId/end', authenticateToken, async (req, res) => {
  try {
    const { shiftId } = req.params;
    const { latitude, longitude, mileage } = req.body;

    const result = await pool.query(
      `UPDATE shifts 
       SET end_time = NOW(), end_latitude = $1, end_longitude = $2, 
           mileage = $3, status = 'completed'
       WHERE id = $4 AND user_id = $5 AND status = 'active'
       RETURNING *`,
      [latitude, longitude, mileage, shiftId, req.user.userId]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Active shift not found' });
    }

    res.json({ shift: result.rows[0] });
  } catch (error) {
    console.error('End shift error:', error);
    res.status(500).json({ error: 'Failed to end shift' });
  }
});

app.post('/api/shifts/:shiftId/locations', authenticateToken, async (req, res) => {
  try {
    const { shiftId } = req.params;
    const { latitude, longitude } = req.body;

    await pool.query(
      `INSERT INTO shift_locations (shift_id, latitude, longitude, recorded_at)
       VALUES ($1, $2, $3, NOW())`,
      [shiftId, latitude, longitude]
    );

    res.status(201).json({ message: 'Location tracked' });
  } catch (error) {
    console.error('Track location error:', error);
    res.status(500).json({ error: 'Failed to track location' });
  }
});

app.get('/api/shifts', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT * FROM shifts 
       WHERE user_id = $1 
       ORDER BY start_time DESC`,
      [req.user.userId]
    );

    res.json({ shifts: result.rows });
  } catch (error) {
    console.error('Get shifts error:', error);
    res.status(500).json({ error: 'Failed to fetch shifts' });
  }
});

app.get('/api/shifts/active', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT * FROM shifts 
       WHERE user_id = $1 AND status = 'active'
       ORDER BY start_time DESC LIMIT 1`,
      [req.user.userId]
    );

    res.json({ shift: result.rows[0] || null });
  } catch (error) {
    console.error('Get active shift error:', error);
    res.status(500).json({ error: 'Failed to fetch active shift' });
  }
});

// GAS REQUEST ROUTES
app.post('/api/gas-requests', authenticateToken, upload.single('receipt'), async (req, res) => {
  try {
    const { amount, station } = req.body;
    const receiptPath = req.file ? req.file.path : null;

    const result = await pool.query(
      `INSERT INTO gas_requests (user_id, amount, station, receipt_path, status)
       VALUES ($1, $2, $3, $4, 'pending')
       RETURNING *`,
      [req.user.userId, amount, station, receiptPath]
    );

    res.status(201).json({ gasRequest: result.rows[0] });
  } catch (error) {
    console.error('Submit gas request error:', error);
    res.status(500).json({ error: 'Failed to submit gas request' });
  }
});

app.get('/api/gas-requests', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT * FROM gas_requests 
       WHERE user_id = $1 
       ORDER BY created_at DESC`,
      [req.user.userId]
    );

    res.json({ gasRequests: result.rows });
  } catch (error) {
    console.error('Get gas requests error:', error);
    res.status(500).json({ error: 'Failed to fetch gas requests' });
  }
});

// ADMIN ROUTES
app.get('/api/admin/drivers', authenticateToken, verifyAdmin, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT id, email, first_name, last_name, phone_number, status, created_at
       FROM users 
       WHERE role = 'driver'
       ORDER BY created_at DESC`
    );

    res.json({ drivers: result.rows });
  } catch (error) {
    console.error('Get drivers error:', error);
    res.status(500).json({ error: 'Failed to fetch drivers' });
  }
});

app.get('/api/admin/shifts', authenticateToken, verifyAdmin, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT s.*, u.first_name, u.last_name, u.email
       FROM shifts s
       JOIN users u ON s.user_id = u.id
       ORDER BY s.start_time DESC`
    );

    res.json({ shifts: result.rows });
  } catch (error) {
    console.error('Get all shifts error:', error);
    res.status(500).json({ error: 'Failed to fetch shifts' });
  }
});

app.get('/api/admin/gas-requests', authenticateToken, verifyAdmin, async (req, res) => {
  try {
    const { status } = req.query;
    
    let query = `
      SELECT gr.*, u.first_name, u.last_name, u.email
      FROM gas_requests gr
      JOIN users u ON gr.user_id = u.id
    `;
    const params = [];
    
    if (status) {
      query += ' WHERE gr.status = $1';
      params.push(status);
    }
    
    query += ' ORDER BY gr.created_at DESC';

    const result = await pool.query(query, params);
    res.json({ gasRequests: result.rows });
  } catch (error) {
    console.error('Get gas requests error:', error);
    res.status(500).json({ error: 'Failed to fetch gas requests' });
  }
});

app.put('/api/admin/gas-requests/:requestId', authenticateToken, verifyAdmin, async (req, res) => {
  try {
    const { requestId } = req.params;
    const { status, notes } = req.body;

    if (!['approved', 'rejected'].includes(status)) {
      return res.status(400).json({ error: 'Invalid status' });
    }

    const result = await pool.query(
      `UPDATE gas_requests 
       SET status = $1, admin_notes = $2, reviewed_at = NOW(), reviewed_by = $3
       WHERE id = $4
       RETURNING *`,
      [status, notes, req.user.userId, requestId]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Gas request not found' });
    }

    res.json({ gasRequest: result.rows[0] });
  } catch (error) {
    console.error('Update gas request error:', error);
    res.status(500).json({ error: 'Failed to update gas request' });
  }
});

app.put('/api/admin/drivers/:driverId', authenticateToken, verifyAdmin, async (req, res) => {
  try {
    const { driverId } = req.params;
    const { status } = req.body;

    if (!['active', 'inactive', 'suspended'].includes(status)) {
      return res.status(400).json({ error: 'Invalid status' });
    }

    const result = await pool.query(
      `UPDATE users 
       SET status = $1
       WHERE id = $2 AND role = 'driver'
       RETURNING id, email, first_name, last_name, status`,
      [status, driverId]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Driver not found' });
    }

    res.json({ driver: result.rows[0] });
  } catch (error) {
    console.error('Update driver error:', error);
    res.status(500).json({ error: 'Failed to update driver' });
  }
});

app.get('/api/admin/stats', authenticateToken, verifyAdmin, async (req, res) => {
  try {
    const stats = await pool.query(`
      SELECT 
        (SELECT COUNT(*) FROM users WHERE role = 'driver' AND status = 'active') as active_drivers,
        (SELECT COUNT(*) FROM shifts WHERE status = 'active') as active_shifts,
        (SELECT COUNT(*) FROM gas_requests WHERE status = 'pending') as pending_gas_requests,
        (SELECT COALESCE(SUM(mileage), 0) FROM shifts WHERE DATE(start_time) = CURRENT_DATE) as today_mileage,
        (SELECT COALESCE(SUM(amount), 0) FROM gas_requests WHERE status = 'approved' AND DATE(created_at) = CURRENT_DATE) as today_gas_expenses
    `);

    res.json({ stats: stats.rows[0] });
  } catch (error) {
    console.error('Get stats error:', error);
    res.status(500).json({ error: 'Failed to fetch stats' });
  }
});

// DATABASE INITIALIZATION
const initDatabase = async () => {
  try {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        email VARCHAR(255) UNIQUE NOT NULL,
        password VARCHAR(255) NOT NULL,
        first_name VARCHAR(100),
        last_name VARCHAR(100),
        phone_number VARCHAR(20),
        role VARCHAR(20) DEFAULT 'driver',
        status VARCHAR(20) DEFAULT 'active',
        created_at TIMESTAMP DEFAULT NOW()
      );

      CREATE TABLE IF NOT EXISTS shifts (
        id SERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES users(id),
        start_time TIMESTAMP NOT NULL,
        end_time TIMESTAMP,
        start_latitude DECIMAL(10, 8),
        start_longitude DECIMAL(11, 8),
        end_latitude DECIMAL(10, 8),
        end_longitude DECIMAL(11, 8),
        mileage DECIMAL(10, 2),
        status VARCHAR(20) DEFAULT 'active',
        created_at TIMESTAMP DEFAULT NOW()
      );

      CREATE TABLE IF NOT EXISTS shift_locations (
        id SERIAL PRIMARY KEY,
        shift_id INTEGER REFERENCES shifts(id),
        latitude DECIMAL(10, 8),
        longitude DECIMAL(11, 8),
        recorded_at TIMESTAMP DEFAULT NOW()
      );

      CREATE TABLE IF NOT EXISTS gas_requests (
        id SERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES users(id),
        amount DECIMAL(10, 2) NOT NULL,
        station VARCHAR(255),
        receipt_path VARCHAR(500),
        status VARCHAR(20) DEFAULT 'pending',
        admin_notes TEXT,
        reviewed_by INTEGER REFERENCES users(id),
        reviewed_at TIMESTAMP,
        created_at TIMESTAMP DEFAULT NOW()
      );

      CREATE INDEX IF NOT EXISTS idx_shifts_user_id ON shifts(user_id);
      CREATE INDEX IF NOT EXISTS idx_gas_requests_user_id ON gas_requests(user_id);
      CREATE INDEX IF NOT EXISTS idx_gas_requests_status ON gas_requests(status);
    `);

    const adminExists = await pool.query('SELECT id FROM users WHERE email = $1', ['admin@example.com']);
    if (adminExists.rows.length === 0) {
      const hashedPassword = await bcrypt.hash('admin123', 10);
      await pool.query(
        `INSERT INTO users (email, password, first_name, last_name, role, status)
         VALUES ($1, $2, 'Admin', 'User', 'admin', 'active')`,
        ['admin@example.com', hashedPassword]
      );
      console.log('✅ Default admin created: admin@example.com / admin123');
    }

    console.log('✅ Database initialized successfully');
  } catch (error) {
    console.error('❌ Database initialization error:', error);
  }
};

const PORT = process.env.PORT || 3001;

app.listen(PORT, async () => {
  await initDatabase();
  console.log(`🚀 Server running on port ${PORT}`);
});
