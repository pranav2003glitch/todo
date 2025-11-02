import express from 'express';
import cors from 'cors';
import pkg from 'sqlite3';
import path from 'path';
import { fileURLToPath } from 'url';
import { config } from 'dotenv';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
config();
const { verbose } = pkg;
const sqlite3 = verbose();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key-here';

app.use(cors());
app.use(express.json());

// Initialize SQLite database
const dbPath = path.join(__dirname, 'notes.db');
const db = new sqlite3.Database(dbPath);

// Create tables
db.serialize(() => {
  // Users table
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    createdAt DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);

  // Notes table
  db.run(`CREATE TABLE IF NOT EXISTS notes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT NOT NULL,
    content TEXT NOT NULL,
    isPinned INTEGER DEFAULT 0,
    color TEXT DEFAULT '#ffffff',
    userId INTEGER NOT NULL,
    createdAt DATETIME DEFAULT CURRENT_TIMESTAMP,
    updatedAt DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (userId) REFERENCES users (id)
  )`);
});

// Middleware to verify JWT token
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1]; // Bearer TOKEN

  if (!token) {
    return res.status(401).json({ error: 'Access token required' });
  }

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ error: 'Invalid or expired token' });
    }
    req.user = user;
    next();
  });
};

// Auth Routes

// Register
app.post('/api/auth/register', async (req, res) => {
  const { email, password } = req.body;
    console.log("Email:", email, " ", "Password:", password);
  if (!email || !password) {
    return res.status(400).json({ error: 'Email and password are required' });
  }

  if (password.length < 6) {
    return res.status(400).json({ error: 'Password must be at least 6 characters long' });
  }

  try {
    // Check if user already exists
    db.get('SELECT id FROM users WHERE email = ?', [email], async (err, row) => {
      if (err) {
        return res.status(500).json({ error: 'Database error' });
      }

      if (row) {
        return res.status(400).json({ error: 'User already exists' });
      }

      // Hash password
      const hashedPassword = await bcrypt.hash(password, 12);
      console.log(hashedPassword)
      // Create user
      db.run('INSERT INTO users (email, password) VALUES (?, ?)', [email, hashedPassword], function(err) {
        if (err) {
          return res.status(500).json({ error: 'Failed to create user' });
        }

        // Generate JWT token
        const token = jwt.sign({ userId: this.lastID, email }, JWT_SECRET, { expiresIn: '7d' });

        res.status(201).json({
          message: 'User created successfully',
          token,
          user: { id: this.lastID, email }
        });
      });
    });
  } catch (error) {
    res.status(500).json({ error: 'Server error' });
  }
});

// Login
app.post('/api/auth/login', (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ error: 'Email and password are required' });
  }

  // Find user
  db.get('SELECT * FROM users WHERE email = ?', [email], async (err, user) => {
    if (err) {
      return res.status(500).json({ error: 'Database error' });
    }

    if (!user) {
      return res.status(400).json({ error: 'Invalid credentials' });
    }

    // Check password
    const isValidPassword = await bcrypt.compare(password, user.password);
    if (!isValidPassword) {
      return res.status(400).json({ error: 'Invalid credentials' });
    }

    // Generate JWT token
    const token = jwt.sign({ userId: user.id, email: user.email }, JWT_SECRET, { expiresIn: '7d' });

    res.json({
      message: 'Login successful',
      token,
      user: { id: user.id, email: user.email }
    });
  });
});

// Notes Routes (Protected)

// Get all notes for user
app.get('/api/notes', authenticateToken, (req, res) => {
  const userId = req.user.userId;
  const search = req.query.search;

  let query = `
    SELECT * FROM notes 
    WHERE userId = ?
    ORDER BY isPinned DESC, updatedAt DESC
  `;

  if (search) {
    query = `
      SELECT * FROM notes 
      WHERE userId = ? AND (title LIKE ? OR content LIKE ?)
      ORDER BY isPinned DESC, updatedAt DESC
    `;
    db.all(query, [userId, `%${search}%`, `%${search}%`], (err, rows) => {
      if (err) {
        res.status(500).json({ error: err.message });
        return;
      }
      res.json(rows);
    });
  } else {
    db.all(query, [userId], (err, rows) => {
      if (err) {
        res.status(500).json({ error: err.message });
        return;
      }
      res.json(rows);
    });
  }
});

// Get single note by ID
app.get('/api/notes/:id', authenticateToken, (req, res) => {
  const id = req.params.id;
  const userId = req.user.userId;

  db.get('SELECT * FROM notes WHERE id = ? AND userId = ?', [id, userId], (err, row) => {
    if (err) {
      res.status(500).json({ error: err.message });
      return;
    }
    if (!row) {
      res.status(404).json({ error: 'Note not found' });
      return;
    }
    res.json(row);
  });
});

// Create new note
app.post('/api/notes', authenticateToken, (req, res) => {
  const { title, content, color = '#ffffff' } = req.body;
  const userId = req.user.userId;

  if (!title || !content) {
    return res.status(400).json({ error: 'Title and content are required' });
  }

  const query = `
    INSERT INTO notes (title, content, color, userId) 
    VALUES (?, ?, ?, ?)
  `;

  db.run(query, [title, content, color, userId], function(err) {
    if (err) {
      res.status(500).json({ error: err.message });
      return;
    }
    res.json({ 
      id: this.lastID, 
      title, 
      content, 
      color,
      isPinned: 0,
      userId,
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString()
    });
  });
});

// Update note
app.put('/api/notes/:id', authenticateToken, (req, res) => {
  const id = req.params.id;
  const userId = req.user.userId;
  const { title, content, isPinned, color } = req.body;

  if (!title || !content) {
    return res.status(400).json({ error: 'Title and content are required' });
  }

  const query = `
    UPDATE notes 
    SET title = ?, content = ?, isPinned = ?, color = ?, updatedAt = CURRENT_TIMESTAMP 
    WHERE id = ? AND userId = ?
  `;

  db.run(query, [title, content, isPinned ? 1 : 0, color, id, userId], function(err) {
    if (err) {
      res.status(500).json({ error: err.message });
      return;
    }
    if (this.changes === 0) {
      res.status(404).json({ error: 'Note not found' });
      return;
    }
    res.json({ message: 'Note updated successfully' });
  });
});

// Delete note
app.delete('/api/notes/:id', authenticateToken, (req, res) => {
  const id = req.params.id;
  const userId = req.user.userId;

  db.run('DELETE FROM notes WHERE id = ? AND userId = ?', [id, userId], function(err) {
    if (err) {
      res.status(500).json({ error: err.message });
      return;
    }
    if (this.changes === 0) {
      res.status(404).json({ error: 'Note not found' });
      return;
    }
    res.json({ message: 'Note deleted successfully' });
  });
});

// Toggle pin status
app.patch('/api/notes/:id/pin', authenticateToken, (req, res) => {
  const id = req.params.id;
  const userId = req.user.userId;

  db.run('UPDATE notes SET isPinned = NOT isPinned, updatedAt = CURRENT_TIMESTAMP WHERE id = ? AND userId = ?', [id, userId], function(err) {
    if (err) {
      res.status(500).json({ error: err.message });
      return;
    }
    if (this.changes === 0) {
      res.status(404).json({ error: 'Note not found' });
      return;
    }
    res.json({ message: 'Pin status toggled successfully' });
  });
});

// Get user profile
app.get('/api/user/profile', authenticateToken, (req, res) => {
  const userId = req.user.userId;

  db.get('SELECT id, email, createdAt FROM users WHERE id = ?', [userId], (err, user) => {
    if (err) {
      res.status(500).json({ error: err.message });
      return;
    }
    if (!user) {
      res.status(404).json({ error: 'User not found' });
      return;
    }
    res.json(user);
  });
});

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
  console.log(`API endpoints available at http://localhost:${PORT}/api`);
});