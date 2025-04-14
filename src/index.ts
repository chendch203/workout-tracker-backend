import express from 'express';
import cors from 'cors';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcryptjs';
import { open } from 'sqlite';
import sqlite3 from 'sqlite3';
import path from 'path';

const app = express();
const port = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key';
const ALLOWED_ORIGINS = (process.env.ALLOWED_ORIGINS || 'http://localhost:3000').split(',');

// 在 Vercel 环境中使用内存数据库
const isDevelopment = process.env.NODE_ENV !== 'production';
const dbPath = isDevelopment ? path.join(__dirname, '../database.sqlite') : ':memory:';

// 数据库初始化
async function initializeDatabase() {
  const db = await open({
    filename: dbPath,
    driver: sqlite3.Database
  });

  // 创建用户表
  await db.exec(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE,
      password TEXT
    )
  `);

  // 创建运动记录表
  await db.exec(`
    CREATE TABLE IF NOT EXISTS workouts (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER,
      date TEXT,
      type TEXT,
      subtype TEXT,
      FOREIGN KEY (user_id) REFERENCES users (id)
    )
  `);

  return db;
}

// 初始化数据库
const dbPromise = initializeDatabase();

// 中间件
app.use(express.json());
app.use(cors({
  origin: (origin, callback) => {
    if (!origin || ALLOWED_ORIGINS.includes(origin)) {
      callback(null, true);
    } else {
      callback(new Error('Not allowed by CORS'));
    }
  },
  credentials: true
}));

// 健康检查端点
app.get('/health', (req, res) => {
  res.json({ status: 'ok' });
});

// API 路由
app.post('/api/register', async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password) {
      return res.status(400).json({ error: 'Username and password are required' });
    }

    const db = await dbPromise;

    // 检查用户名是否已存在
    const existingUser = await db.get('SELECT id FROM users WHERE username = ?', username);
    if (existingUser) {
      return res.status(400).json({ error: 'Username already exists' });
    }

    // 加密密码
    const hashedPassword = await bcrypt.hash(password, 10);

    // 创建新用户
    const result = await db.run(
      'INSERT INTO users (username, password) VALUES (?, ?)',
      [username, hashedPassword]
    );

    const token = jwt.sign({ userId: result.lastID }, JWT_SECRET);
    res.json({ token });
  } catch (error) {
    console.error('Register error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.post('/api/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password) {
      return res.status(400).json({ error: 'Username and password are required' });
    }

    const db = await dbPromise;

    // 查找用户
    const user = await db.get('SELECT * FROM users WHERE username = ?', username);
    if (!user) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    // 验证密码
    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const token = jwt.sign({ userId: user.id }, JWT_SECRET);
    res.json({ token });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// 验证 token 的中间件
const authenticateToken = (req: any, res: any, next: any) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'Authentication required' });
  }

  jwt.verify(token, JWT_SECRET, (err: any, user: any) => {
    if (err) {
      return res.status(403).json({ error: 'Invalid token' });
    }
    req.user = user;
    next();
  });
};

// 运动记录相关的路由
app.post('/api/workouts', authenticateToken, async (req: any, res) => {
  try {
    const { date, type, subtype } = req.body;
    if (!date || !type || !subtype) {
      return res.status(400).json({ error: 'Date, type and subtype are required' });
    }

    const db = await dbPromise;
    const result = await db.run(
      'INSERT INTO workouts (user_id, date, type, subtype) VALUES (?, ?, ?, ?)',
      [req.user.userId, date, type, subtype]
    );

    res.json({ id: result.lastID });
  } catch (error) {
    console.error('Create workout error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.get('/api/workouts', authenticateToken, async (req: any, res) => {
  try {
    const db = await dbPromise;
    const workouts = await db.all(
      'SELECT * FROM workouts WHERE user_id = ? ORDER BY date DESC',
      req.user.userId
    );
    res.json(workouts);
  } catch (error) {
    console.error('Get workouts error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// 导出 express app 以供 Vercel 使用
export default app;

// 仅在非 Vercel 环境下启动服务器
if (process.env.NODE_ENV !== 'production') {
  app.listen(port, () => {
    console.log(`Server is running on port ${port}`);
  });
}
