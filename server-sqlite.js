const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const sqlite3 = require('sqlite3').verbose();
const multer = require('multer');
require('dotenv').config();

const app = express();
const upload = multer({ dest: 'uploads/' });
const db = new sqlite3.Database('./database.sqlite');

app.use(cors());
app.use(express.json());
app.use('/uploads', express.static('uploads'));

const JWT_SECRET = 'your-secret-key-12345';

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

app.post('/api/auth/register', authenticateToken, verifyAdmin, async (req, res) => {
  try {
    const { email, password, firstName, lastName, phoneNumber } = req.body;
    const hashedPassword = await bcrypt.hash(password, 10);
    
    db.run(
      'INSERT INTO users (email, password, first_name, last_name, phone_number, role, status) VALUES (?, ?, ?, ?, ?, ?, ?)',
      [email, hashedPassword, firstName, lastName, phoneNumber, 'driver', 'active'],
      function(err) {
        if (err) return res.status(400).json({ error: 'User already exists' });
        res.status(201).json({ user: { id: this.lastID, email, first_name: firstName, last_name: lastName } });
      }
    );
  } catch (error) {
    res.status(500).json({ error: 'Registration failed' });
  }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    db.get('SELECT * FROM users WHERE email = ?', [email], async (err, user) => {
      if (err || !user) return res.status(401).json({ error: 'Invalid credentials' });
      if (user.status !== 'active') return res.status(403).json({ error: 'Account inactive' });
      
      const validPassword = await bcrypt.compare(password, user.password);
      if (!validPassword) return res.status(401).json({ error: 'Invalid credentials' });
      
      const token = jwt.sign({ userId: user.id, email: user.email, role: user.role }, JWT_SECRET, { expiresIn: '7d' });
      res.json({ token, user: { id: user.id, email: user.email, firstName: user.first_name, lastName: user.last_name, role: user.role } });
    });
  } catch (error) {
    res.status(500).json({ error: 'Login failed' });
  }
});

app.post('/api/shifts/start', authenticateToken, (req, res) => {
  const { latitude, longitude } = req.body;
  db.run(
    "INSERT INTO shifts (user_id, start_time, start_latitude, start_longitude, status) VALUES (?, datetime('now'), ?, ?, ?)",
    [req.user.userId, latitude, longitude, 'active'],
    function(err) {
      if (err) return res.status(500).json({ error: 'Failed to start shift' });
      db.get('SELECT * FROM shifts WHERE id = ?', [this.lastID], (err, shift) => {
        res.status(201).json({ shift });
      });
    }
  );
});

app.put('/api/shifts/:shiftId/end', authenticateToken, (req, res) => {
  const { shiftId } = req.params;
  const { latitude, longitude, mileage } = req.body;
  db.run(
    "UPDATE shifts SET end_time = datetime('now'), end_latitude = ?, end_longitude = ?, mileage = ?, status = ? WHERE id = ? AND user_id = ?",
    [latitude, longitude, mileage, 'completed', shiftId, req.user.userId],
    function(err) {
      if (err || this.changes === 0) return res.status(404).json({ error: 'Shift not found' });
      db.get('SELECT * FROM shifts WHERE id = ?', [shiftId], (err, shift) => {
        res.json({ shift });
      });
    }
  );
});

app.post('/api/shifts/:shiftId/locations', authenticateToken, (req, res) => {
  const { shiftId } = req.params;
  const { latitude, longitude } = req.body;
  db.run('INSERT INTO shift_locations (shift_id, latitude, longitude) VALUES (?, ?, ?)',
    [shiftId, latitude, longitude],
    (err) => {
      if (err) return res.status(500).json({ error: 'Failed to track' });
      res.status(201).json({ message: 'Location tracked' });
    }
  );
});

app.get('/api/shifts', authenticateToken, (req, res) => {
  db.all('SELECT * FROM shifts WHERE user_id = ? ORDER BY start_time DESC', [req.user.userId], (err, shifts) => {
    if (err) return res.status(500).json({ error: 'Failed to fetch' });
    res.json({ shifts });
  });
});

app.get('/api/shifts/active', authenticateToken, (req, res) => {
  db.get('SELECT * FROM shifts WHERE user_id = ? AND status = ? ORDER BY start_time DESC LIMIT 1', 
    [req.user.userId, 'active'], (err, shift) => {
      res.json({ shift: shift || null });
    }
  );
});

app.post('/api/gas-requests', authenticateToken, upload.single('receipt'), (req, res) => {
  const { amount, station } = req.body;
  const receiptPath = req.file ? req.file.path : null;
  db.run('INSERT INTO gas_requests (user_id, amount, station, receipt_path, status) VALUES (?, ?, ?, ?, ?)',
    [req.user.userId, amount, station, receiptPath, 'pending'],
    function(err) {
      if (err) return res.status(500).json({ error: 'Failed to submit' });
      db.get('SELECT * FROM gas_requests WHERE id = ?', [this.lastID], (err, gasRequest) => {
        res.status(201).json({ gasRequest });
      });
    }
  );
});

app.get('/api/gas-requests', authenticateToken, (req, res) => {
  db.all('SELECT * FROM gas_requests WHERE user_id = ? ORDER BY created_at DESC', [req.user.userId], (err, gasRequests) => {
    if (err) return res.status(500).json({ error: 'Failed to fetch' });
    res.json({ gasRequests });
  });
});

app.get('/api/admin/drivers', authenticateToken, verifyAdmin, (req, res) => {
  db.all('SELECT id, email, first_name, last_name, phone_number, status, created_at FROM users WHERE role = ?', ['driver'],
    (err, drivers) => {
      if (err) return res.status(500).json({ error: 'Failed to fetch' });
      res.json({ drivers });
    }
  );
});

app.get('/api/admin/shifts', authenticateToken, verifyAdmin, (req, res) => {
  db.all('SELECT s.*, u.first_name, u.last_name, u.email FROM shifts s JOIN users u ON s.user_id = u.id ORDER BY s.start_time DESC',
    (err, shifts) => {
      if (err) return res.status(500).json({ error: 'Failed to fetch' });
      res.json({ shifts });
    }
  );
});

app.get('/api/admin/gas-requests', authenticateToken, verifyAdmin, (req, res) => {
  const { status } = req.query;
  let query = 'SELECT gr.*, u.first_name, u.last_name, u.email FROM gas_requests gr JOIN users u ON gr.user_id = u.id';
  const params = [];
  if (status) { query += ' WHERE gr.status = ?'; params.push(status); }
  query += ' ORDER BY gr.created_at DESC';
  db.all(query, params, (err, gasRequests) => {
    if (err) return res.status(500).json({ error: 'Failed to fetch' });
    res.json({ gasRequests });
  });
});

app.put('/api/admin/gas-requests/:requestId', authenticateToken, verifyAdmin, (req, res) => {
  const { requestId } = req.params;
  const { status, notes } = req.body;
  db.run("UPDATE gas_requests SET status = ?, admin_notes = ?, reviewed_at = datetime('now'), reviewed_by = ? WHERE id = ?",
    [status, notes, req.user.userId, requestId],
    function(err) {
      if (err || this.changes === 0) return res.status(404).json({ error: 'Not found' });
      db.get('SELECT * FROM gas_requests WHERE id = ?', [requestId], (err, gasRequest) => {
        res.json({ gasRequest });
      });
    }
  );
});

app.put('/api/admin/drivers/:driverId', authenticateToken, verifyAdmin, (req, res) => {
  const { driverId } = req.params;
  const { status } = req.body;
  db.run('UPDATE users SET status = ? WHERE id = ? AND role = ?', [status, driverId, 'driver'], function(err) {
    if (err || this.changes === 0) return res.status(404).json({ error: 'Not found' });
    db.get('SELECT id, email, first_name, last_name, status FROM users WHERE id = ?', [driverId], (err, driver) => {
      res.json({ driver });
    });
  });
});

app.get('/api/admin/stats', authenticateToken, verifyAdmin, (req, res) => {
  db.get("SELECT (SELECT COUNT(*) FROM users WHERE role = 'driver' AND status = 'active') as active_drivers, (SELECT COUNT(*) FROM shifts WHERE status = 'active') as active_shifts, (SELECT COUNT(*) FROM gas_requests WHERE status = 'pending') as pending_gas_requests, (SELECT COALESCE(SUM(mileage), 0) FROM shifts WHERE DATE(start_time) = DATE('now')) as today_mileage, (SELECT COALESCE(SUM(amount), 0) FROM gas_requests WHERE status = 'approved' AND DATE(created_at) = DATE('now')) as today_gas_expenses",
    (err, stats) => {
      if (err) return res.status(500).json({ error: 'Failed to fetch' });
      res.json({ stats });
    }
  );
});

const initDatabase = async () => {
  db.serialize(() => {
    db.run('CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, email TEXT UNIQUE NOT NULL, password TEXT NOT NULL, first_name TEXT, last_name TEXT, phone_number TEXT, role TEXT DEFAULT "driver", status TEXT DEFAULT "active", created_at DATETIME DEFAULT CURRENT_TIMESTAMP)');
    db.run('CREATE TABLE IF NOT EXISTS shifts (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, start_time DATETIME NOT NULL, end_time DATETIME, start_latitude REAL, start_longitude REAL, end_latitude REAL, end_longitude REAL, mileage REAL, status TEXT DEFAULT "active", created_at DATETIME DEFAULT CURRENT_TIMESTAMP)');
    db.run('CREATE TABLE IF NOT EXISTS shift_locations (id INTEGER PRIMARY KEY AUTOINCREMENT, shift_id INTEGER, latitude REAL, longitude REAL, recorded_at DATETIME DEFAULT CURRENT_TIMESTAMP)');
    db.run('CREATE TABLE IF NOT EXISTS gas_requests (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, amount REAL NOT NULL, station TEXT, receipt_path TEXT, status TEXT DEFAULT "pending", admin_notes TEXT, reviewed_by INTEGER, reviewed_at DATETIME, created_at DATETIME DEFAULT CURRENT_TIMESTAMP)');

    db.get('SELECT id FROM users WHERE email = ?', ['admin@example.com'], async (err, row) => {
      if (!row) {
        const hashedPassword = await bcrypt.hash('admin123', 10);
        db.run('INSERT INTO users (email, password, first_name, last_name, role, status) VALUES (?, ?, ?, ?, ?, ?)',
          ['admin@example.com', hashedPassword, 'Admin', 'User', 'admin', 'active'],
          () => console.log('✅ Default admin created: admin@example.com / admin123')
        );
      }
    });

    console.log('✅ Database initialized successfully');
  });
};

const PORT = 3001;

app.listen(PORT, () => {
  initDatabase();
  console.log('🚀 Server running on port ' + PORT);
});
