const express = require('express');
const cors = require('cors');
const sqlite3 = require('sqlite3').verbose();
const bodyParser = require('body-parser');
const bcrypt = require('bcrypt');

const app = express();
const port = process.env.PORT || 3000;

// middleware
app.use(cors());
app.use(bodyParser.json());

// قاعدة بيانات SQLite داخل ملف (وليس في الذاكرة)
const db = new sqlite3.Database('./db.sqlite', (err) => {
  if (err) return console.error('❌ فشل فتح قاعدة البيانات:', err.message);
  console.log('📦 قاعدة البيانات جاهزة');
});

// إنشاء جدول المستخدمين إذا غير موجود
db.serialize(() => {
  db.run(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL,
      phone TEXT NOT NULL UNIQUE,
      password TEXT NOT NULL
    )
  `);
});

// ✅ تسجيل مستخدم جديد
app.post('/register', async (req, res) => {
  const { name, phone, password } = req.body;

  if (!name || !phone || !password) {
    return res.status(400).json({ message: 'يرجى تعبئة جميع الحقول' });
  }

  try {
    const hashedPassword = await bcrypt.hash(password, 10);

    db.run(
      'INSERT INTO users (name, phone, password) VALUES (?, ?, ?)',
      [name, phone, hashedPassword],
      function (err) {
        if (err) {
          return res.status(500).json({ message: 'الرقم مستخدم مسبقاً' });
        }

        res.status(201).json({
          message: 'تم التسجيل بنجاح',
          userId: this.lastID,
        });
      }
    );
  } catch (error) {
    res.status(500).json({ message: 'خطأ أثناء التسجيل' });
  }
});

// ✅ تسجيل الدخول
app.post('/login', (req, res) => {
  const { phone, password } = req.body;

  db.get(
    'SELECT * FROM users WHERE phone = ?',
    [phone],
    async (err, user) => {
      if (err || !user) {
        return res.status(400).json({ message: 'رقم الهاتف غير صحيح' });
      }

      const match = await bcrypt.compare(password, user.password);
      if (!match) {
        return res.status(401).json({ message: 'كلمة المرور غير صحيحة' });
      }

      res.json({ message: 'تم تسجيل الدخول بنجاح', user });
    }
  );
});

// ✅ جلب معلومات مستخدم
app.get('/user/:id', (req, res) => {
  const { id } = req.params;

  db.get(
    'SELECT id, name, phone FROM users WHERE id = ?',
    [id],
    (err, user) => {
      if (err || !user) {
        return res.status(404).json({ message: 'المستخدم غير موجود' });
      }

      res.json(user);
    }
  );
});

// ✅ بدء تشغيل السيرفر
app.listen(port, () => {
  console.log(`✅ السيرفر يعمل على http://localhost:${port}`);
});