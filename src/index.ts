import express, { Request, Response, NextFunction } from 'express';
import cors from 'cors';
import sqlite3 from 'sqlite3';
import { open } from 'sqlite';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import path from 'path';

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key';
const ALLOWED_ORIGINS = process.env.ALLOWED_ORIGINS ? 
    process.env.ALLOWED_ORIGINS.split(',') : 
    ['http://localhost:3001', 'http://localhost:3002'];

interface AuthRequest extends Request {
    user?: {
        userId: number;
    };
}

// 在 Vercel 环境中使用内存数据库
const isDevelopment = process.env.NODE_ENV !== 'production';
const dbPath = isDevelopment ? path.join(__dirname, 'database.sqlite') : ':memory:';

// 数据库初始化
async function initializeDatabase() {
    const db = await open({
        filename: dbPath,
        driver: sqlite3.Database
    });

    await db.exec(`
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS workouts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            type TEXT NOT NULL,
            subtype TEXT NOT NULL,
            date TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users (id)
        );
    `);

    return db;
}

let db: any;
initializeDatabase().then((database) => {
    db = database;
    console.log('Database initialized');
});

// 配置 CORS
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

app.use(express.json());

// 健康检查端点
app.get('/health', (_, res) => {
    res.json({ status: 'ok' });
});

// 用户注册
app.post('/api/register', async (req: Request, res: Response) => {
    const { username, password } = req.body;

    if (!username || !password) {
        return res.status(400).json({ error: '用户名和密码都是必需的' });
    }

    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        await db.run(
            'INSERT INTO users (username, password) VALUES (?, ?)',
            [username, hashedPassword]
        );
        res.status(201).json({ message: '注册成功' });
    } catch (error) {
        res.status(400).json({ error: '用户名已存在' });
    }
});

// 用户登录
app.post('/api/login', async (req: Request, res: Response) => {
    const { username, password } = req.body;

    if (!username || !password) {
        return res.status(400).json({ error: '用户名和密码都是必需的' });
    }

    try {
        const user = await db.get(
            'SELECT * FROM users WHERE username = ?',
            username
        );

        if (!user || !(await bcrypt.compare(password, user.password))) {
            return res.status(401).json({ error: '用户名或密码错误' });
        }

        const token = jwt.sign({ userId: user.id }, JWT_SECRET, { expiresIn: '24h' });
        res.json({ token, username });
    } catch (error) {
        res.status(500).json({ error: '服务器错误' });
    }
});

// 验证 JWT token 的中间件
const authenticateToken = (req: AuthRequest, res: Response, next: NextFunction) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        return res.status(401).json({ error: '未登录' });
    }

    jwt.verify(token, JWT_SECRET, (err: any, user: any) => {
        if (err) {
            return res.status(403).json({ error: '登录已过期' });
        }
        req.user = user;
        next();
    });
};

// 添加运动记录
app.post('/api/workouts', authenticateToken, async (req: AuthRequest, res: Response) => {
    const { type, subtype, date } = req.body;
    const userId = req.user?.userId;

    if (!userId) {
        return res.status(401).json({ error: '未登录' });
    }

    if (!type || !subtype || !date) {
        return res.status(400).json({ error: '所有字段都是必需的' });
    }

    try {
        await db.run(
            'INSERT INTO workouts (user_id, type, subtype, date) VALUES (?, ?, ?, ?)',
            [userId, type, subtype, date]
        );
        res.status(201).json({ message: '记录添加成功' });
    } catch (error) {
        res.status(500).json({ error: '服务器错误' });
    }
});

// 获取用户的运动记录
app.get('/api/workouts', authenticateToken, async (req: AuthRequest, res: Response) => {
    const userId = req.user?.userId;

    if (!userId) {
        return res.status(401).json({ error: '未登录' });
    }

    try {
        const workouts = await db.all(
            'SELECT * FROM workouts WHERE user_id = ? ORDER BY date DESC',
            userId
        );
        res.json(workouts);
    } catch (error) {
        res.status(500).json({ error: '服务器错误' });
    }
});

app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});
