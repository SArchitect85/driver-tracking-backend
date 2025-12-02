const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const Database = require('better-sqlite3');
const multer = require('multer');
require('dotenv').config();

const app = express();
const upload = multer({ dest: 'uploads/' });
const db = new Database('./database.sqlite');

app.use(cors());
app.use(express.json());
app.use('/uploads', express.static('uploads'));

const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key-12345';

app.get('/health', (req, res) => {
  res.json({ status: 'ok', message: 'Server is running' });
});

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

const verifyAdmin = (req, res, next) => {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Admin access required' });
  }
  next();
};

// AUTH ROUTES
app.post('/api/auth/register', authenticateToken, verifyAdmin, (req, res) => {
  try {
    const { email, password, firstName, lastName, phoneNumber } = req.body;
    const hashedPassword = bcrypt.hashSync(password, 10);
    
    const stmt = db.prepare('INSERT INTO users (email, password, first_name, last_name, phone_number, role, status) VALUES (?, ?, ?, ?, ?, ?, ?)');
    const result = stmt.run(email, hashedPassword, firstName, lastName, phoneNumber, 'driver', 'active');
    
    res.status(201).json({ user: { id: result.lastInsertRowid, email, first_name: firstName, last_name: lastName } });
  } catch (error) {
    res.status(400).json({ error: 'User already exists' });
  }
});

app.post('/api/auth/login', (req, res) => {
  try {
    const { email, password } = req.body;
    const stmt = db.prepare('SELECT * FROM users WHERE email = ?');
    const user = stmt.get(email);
    
    if (!user) return res.status(401).json({ error: 'Invalid credentials' });
    if (user.status !== 'active') return res.status(403).json({ error: 'Account inactive' });
    
    const validPassword = bcrypt.compareSync(password, user.password);
    if (!validPassword) return res.status(401).json({ error: 'Invalid credentials' });
    
    const token = jwt.sign({ userId: user.id, email: user.email, role: user.role }, JWT_SECRET, { expiresIn: '7d' });
    res.json({ token, user: { id: user.id, email: user.email, firstName: user.first_name, lastName: user.last_name, role: user.role } });
  } catch (error) {
    res.status(500).json({ error: 'Login failed' });
  }
});

// SHIFT ROUTES
app.post('/api/shifts/start', authenticateToken, (req, res) => {
  const { latitude, longitude } = req.body;
  const stmt = db.prepare('INSERT INTO shifts (user_id, start_time, start_latitude, start_longitude, status) VALUES (?, datetime("now"), ?, ?, ?)');
  const result = stmt.run(req.user.userId, latitude, longitude, 'active');
  const shift = db.prepare('SELECT * FROM shifts WHERE id = ?').get(result.lastInsertRowid);
  res.status(201).json({ shift });
});

app.put('/api/shifts/:shiftId/end', authenticateToken, (req, res) => {
  const { shiftId } = req.params;
  const { latitude, longitude, mileage } = req.body;
  const stmt = db.prepare('UPDATE shifts SET end_time = datetime("now"), end_latitude = ?, end_longitude = ?, mileage = ?, status = ? WHERE id = ? AND user_id = ?');
  stmt.run(latitude, longitude, mileage, 'completed', shiftId, req.user.userId);
  const shift = db.prepare('SELECT * FROM shifts WHERE id = ?').get(shiftId);
  res.json({ shift });
});

app.post('/api/shifts/:shiftId/locations', authenticateToken, (req, res) => {
  const { shiftId } = req.params;
  const { latitude, longitude } = req.body;
  const stmt = db.prepare('INSERT INTO shift_locations (shift_id, latitude, longitude) VALUES (?, ?, ?)');
  stmt.run(shiftId, latitude, longitude);
  res.status(201).json({ message: 'Location tracked' });
});

app.get('/api/shifts', authenticateToken, (req, res) => {
  const stmt = db.prepare('SELECT * FROM shifts WHERE user_id = ? ORDER BY start_time DESC');
  const shifts = stmt.all(req.user.userId);
  res.json({ shifts });
});

app.get('/api/shifts/active', authenticateToken, (req, res) => {
  const stmt = db.prepare('SELECT * FROM shifts WHERE user_id = ? AND status = ? ORDER BY start_time DESC LIMIT 1');
  const shift = stmt.get(req.user.userId, 'active');
  res.json({ shift: shift || null });
});

// GAS REQUESTS
app.post('/api/gas-requests', authenticateToken, upload.single('receipt'), (req, res) => {
  const { amount, station } = req.body;
  const receiptPath = req.file ? req.file.path : null;
  const stmt = db.prepare('INSERT INTO gas_requests (user_id, amount, station, receipt_path, status, created_at) VALUES (?, ?, ?, ?, ?, datetime("now"))');
  const result = stmt.run(req.user.userId, amount, station, receiptPath, 'pending');
  const gasRequest = db.prepare('SELECT * FROM gas_requests WHERE id = ?').get(result.lastInsertRowid);
  res.status(201).json({ gasRequest });
});

app.get('/api/gas-requests', authenticateToken, (req, res) => {
  const stmt = db.prepare('SELECT * FROM gas_requests WHERE user_id = ? ORDER BY created_at DESC');
  const gasRequests = stmt.all(req.user.userId);
  res.json({ gasRequests });
});

// ADMIN ROUTES
app.get('/api/admin/drivers', authenticateToken, verifyAdmin, (req, res) => {
  const stmt = db.prepare('SELECT id, email, first_name, last_name, phone_number, status, created_at FROM users WHERE role = ?');
  const drivers = stmt.all('driver');
  res.json({ drivers });
});

app.get('/api/admin/shifts', authenticateToken, verifyAdmin, (req, res) => {
  const stmt = db.prepare('SELECT s.*, u.first_name, u.last_name, u.email FROM shifts s JOIN users u ON s.user_id = u.id ORDER BY s.start_time DESC');
  const shifts = stmt.all();
  res.json({ shifts });
});

app.get('/api/admin/gas-requests', authenticateToken, verifyAdmin, (req, res) => {
  const { status } = req.query;
  let stmt;
  if (status) {
    stmt = db.prepare('SELECT gr.*, u.first_name, u.last_name, u.email FROM gas_requests gr JOIN users u ON gr.user_id = u.id WHERE gr.status = ? ORDER BY gr.created_at DESC');
    res.json({ gasRequests: stmt.all(status) });
  } else {
    stmt = db.prepare('SELECT gr.*, u.first_name, u.last_name, u.email FROM gas_requests gr JOIN users u ON gr.user_id = u.id ORDER BY gr.created_at DESC');
    res.json({ gasRequests: stmt.all() });
  }
});

app.put('/api/admin/gas-requests/:requestId', authenticateToken, verifyAdmin, (req, res) => {
  const { requestId } = req.params;
  const { status, notes } = req.body;
  const stmt = db.prepare('UPDATE gas_requests SET status = ?, admin_notes = ?, reviewed_at = datetime("now"), reviewed_by = ? WHERE id = ?');
  stmt.run(status, notes, req.user.userId, requestId);
  const gasRequest = db.prepare('SELECT * FROM gas_requests WHERE id = ?').get(requestId);
  res.json({ gasRequest });
});

app.put('/api/admin/drivers/:driverId', authenticateToken, verifyAdmin, (req, res) => {
  const { driverId } = req.params;
  const { status } = req.body;
  const stmt = db.prepare('UPDATE users SET status = ? WHERE id = ? AND role = ?');
  stmt.run(status, driverId, 'driver');
  const driver = db.prepare('SELECT id, email, first_name, last_name, status FROM users WHERE id = ?').get(driverId);
  res.json({ driver });
});

app.get('/api/admin/stats', authenticateToken, verifyAdmin, (req, res) => {
  const stats = {
    active_drivers: db.prepare("SELECT COUNT(*) as count FROM users WHERE role = 'driver' AND status = 'active'").get().count,
    active_shifts: db.prepare("SELECT COUNT(*) as count FROM shifts WHERE status = 'active'").get().count,
    pending_gas_requests: db.prepare("SELECT COUNT(*) as count FROM gas_requests WHERE status = 'pending'").get().count,
    today_mileage: db.prepare("SELECT COALESCE(SUM(mileage), 0) as total FROM shifts WHERE DATE(start_time) = DATE('now')").get().total,
    today_gas_expenses: db.prepare("SELECT COALESCE(SUM(amount), 0) as total FROM gas_requests WHERE status = 'approved' AND DATE(created_at) = DATE('now')").get().total
  };
  res.json({ stats });
});

// INIT DATABASE
const initDatabase = () => {
  db.exec(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      email TEXT UNIQUE NOT NULL,
      password TEXT NOT NULL,
      first_name TEXT,
      last_name TEXT,
      phone_number TEXT,
      role TEXT DEFAULT 'driver',
      status TEXT DEFAULT 'active',
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );
    CREATE TABLE IF NOT EXISTS shifts (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER,
      start_time DATETIME NOT NULL,
      end_time DATETIME,
      start_latitude REAL,
      start_longitude REAL,
      end_latitude REAL,
      end_longitude REAL,
      mileage REAL,
      status TEXT DEFAULT 'active',
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );
    CREATE TABLE IF NOT EXISTS shift_locations (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      shift_id INTEGER,
      latitude REAL,
      longitude REAL,
      recorded_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );
    CREATE TABLE IF NOT EXISTS gas_requests (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER,
      amount REAL NOT NULL,
      station TEXT,
      receipt_path TEXT,
      status TEXT DEFAULT 'pending',
      admin_notes TEXT,
      reviewed_by INTEGER,
      reviewed_at DATETIME,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );
  `);

  // Create admin if not exists
  const admin = db.prepare('SELECT id FROM users WHERE email = ?').get('admin@example.com');
  if (!admin) {
    const hashedPassword = bcrypt.hashSync('admin123', 10);
    db.prepare('INSERT INTO users (email, password, first_name, last_name, role, status) VALUES (?, ?, ?, ?, ?, ?)').run('admin@example.com', hashedPassword, 'Admin', 'User', 'admin', 'active');
    console.log('✅ Default admin created: admin@example.com / admin123');
  }
  console.log('✅ Database initialized');
};

const PORT = process.env.PORT || 3001;

initDatabase();
app.listen(PORT, '0.0.0.0', () => {
  console.log('🚀 Server running on port ' + PORT);
});
