const express = require('express');
const cors = require('cors');
const Database = require('better-sqlite3');
const bodyParser = require('body-parser');
const bcrypt = require('bcrypt');

const app = express();
const port = process.env.PORT || 3000;

app.use(cors());
app.use(bodyParser.json());

// قاعدة بيانات SQLite دائمة في ملف
const db = new Database('./db.sqlite');

// إنشاء جدول المستخدمين (مرة واحدة فقط)
db.prepare(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    phone TEXT NOT NULL UNIQUE,
    password TEXT NOT NULL
  )
`).run();

// ✅ تسجيل مستخدم جديد
app.post('/register', async (req, res) => {
  const { name, phone, password } = req.body;

  if (!name || !phone || !password) {
    return res.status(400).json({ message: 'يرجى تعبئة جميع الحقول' });
  }

  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    const stmt = db.prepare("INSERT INTO users (name, phone, password) VALUES (?, ?, ?)");
    const result = stmt.run(name, phone, hashedPassword);

    res.status(201).json({ message: 'تم التسجيل بنجاح', userId: result.lastInsertRowid });
  } catch (err) {
    if (err.code === 'SQLITE_CONSTRAINT_UNIQUE') {
      return res.status(400).json({ message: 'رقم الهاتف مستخدم مسبقاً' });
    }
    res.status(500).json({ message: 'حدث خطأ أثناء التسجيل' });
  }
});

// ✅ تسجيل دخول
app.post('/login', async (req, res) => {
  const { phone, password } = req.body;

  try {
    const user = db.prepare("SELECT * FROM users WHERE phone = ?").get(phone);

    if (!user) {
      return res.status(400).json({ message: 'رقم الهاتف غير صحيح' });
    }

    const match = await bcrypt.compare(password, user.password);

    if (!match) {
      return res.status(401).json({ message: 'كلمة المرور غير صحيحة' });
    }

    res.json({ message: 'تم تسجيل الدخول بنجاح', user: { id: user.id, name: user.name, phone: user.phone } });
  } catch (err) {
    res.status(500).json({ message: 'حدث خطأ أثناء تسجيل الدخول' });
  }
});

// ✅ جلب بيانات مستخدم
app.get('/user/:id', (req, res) => {
  const { id } = req.params;

  try {
    const user = db.prepare("SELECT id, name, phone FROM users WHERE id = ?").get(id);

    if (!user) {
      return res.status(404).json({ message: 'المستخدم غير موجود' });
    }

    res.json(user);
  } catch (err) {
    res.status(500).json({ message: 'حدث خطأ أثناء جلب البيانات' });
  }
});

app.listen(port, () => {
  console.log(`✅ السيرفر يعمل على http://localhost:${port}`);
});