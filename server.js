const path = require('node:path');
const fs = require('node:fs');
const crypto = require('node:crypto');
const express = require('express');
const bcrypt = require('bcryptjs');
const Database = require('better-sqlite3');
const QRCode = require('qrcode');

const app = express();
const PORT = Number(process.env.PORT || 3000);
const ROOT = __dirname;
const DATA_DIR = path.join(ROOT, 'data');
fs.mkdirSync(DATA_DIR, { recursive: true });

const db = new Database(path.join(DATA_DIR, 'loggo.sqlite'));
db.pragma('journal_mode = WAL');
db.exec(`
  CREATE TABLE IF NOT EXISTS teachers (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    email TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
  );
  CREATE TABLE IF NOT EXISTS rooms (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    number TEXT NOT NULL UNIQUE,
    code TEXT NOT NULL UNIQUE,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
  );
  CREATE TABLE IF NOT EXISTS move_requests (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    student_name TEXT NOT NULL,
    room_id INTEGER NOT NULL,
    status TEXT NOT NULL DEFAULT 'requested',
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (room_id) REFERENCES rooms(id)
  );
  CREATE TABLE IF NOT EXISTS visits (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    student_name TEXT NOT NULL,
    room_id INTEGER NOT NULL,
    request_id INTEGER,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (room_id) REFERENCES rooms(id),
    FOREIGN KEY (request_id) REFERENCES move_requests(id)
  );
  CREATE TABLE IF NOT EXISTS notifications (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    kind TEXT NOT NULL,
    student_name TEXT NOT NULL,
    room_id INTEGER NOT NULL,
    message TEXT NOT NULL,
    is_read INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (room_id) REFERENCES rooms(id)
  );
`);

const seedTeacher = db.prepare('SELECT id FROM teachers WHERE email = ?').get('teacher@loggo.local');
if (!seedTeacher) {
  db.prepare('INSERT INTO teachers (name, email, password_hash) VALUES (?, ?, ?)').run('야자 감독 선생님', 'teacher@loggo.local', bcrypt.hashSync('loggo2026', 10));
}
const roomSeeds = [['1번 실습실', '101'], ['2번 실습실', '102'], ['3번 실습실', '103'], ['창의 융합실', '201']];
const insertRoom = db.prepare('INSERT OR IGNORE INTO rooms (name, number, code) VALUES (?, ?, ?)');
roomSeeds.forEach(([name, number]) => insertRoom.run(name, number, `LOG-${number}`));

const sessions = new Map();
const createSession = (teacherId) => { const token = crypto.randomBytes(32).toString('hex'); sessions.set(token, { teacherId, createdAt: Date.now() }); return token; };
const getSession = (req) => { const token = req.headers.cookie?.match(/(?:^|; )loggo_session=([^;]+)/)?.[1]; return token ? sessions.get(token) : null; };
const requireTeacher = (req, res, next) => { const session = getSession(req); if (!session) return res.status(401).json({ error: '로그인이 필요합니다.' }); req.teacher = session; next(); };
const isoNow = () => new Date().toISOString();
const roomByCode = (code) => db.prepare('SELECT * FROM rooms WHERE code = ?').get(String(code || '').trim().toUpperCase());

app.use(express.json());
app.use(express.static(ROOT));

app.get('/api/auth/me', (req, res) => {
  const session = getSession(req);
  if (!session) return res.json({ teacher: null });
  const teacher = db.prepare('SELECT id, name, email FROM teachers WHERE id = ?').get(session.teacherId);
  res.json({ teacher });
});

app.post('/api/auth/login', (req, res) => {
  const { email, password } = req.body || {};
  const teacher = db.prepare('SELECT * FROM teachers WHERE email = ?').get(String(email || '').trim().toLowerCase());
  if (!teacher || !bcrypt.compareSync(String(password || ''), teacher.password_hash)) return res.status(401).json({ error: '이메일 또는 비밀번호를 확인해 주세요.' });
  const token = createSession(teacher.id);
  res.setHeader('Set-Cookie', `loggo_session=${token}; HttpOnly; Path=/; SameSite=Lax; Max-Age=43200`);
  res.json({ teacher: { id: teacher.id, name: teacher.name, email: teacher.email } });
});

app.post('/api/auth/logout', (req, res) => {
  const token = req.headers.cookie?.match(/(?:^|; )loggo_session=([^;]+)/)?.[1];
  if (token) sessions.delete(token);
  res.setHeader('Set-Cookie', 'loggo_session=; HttpOnly; Path=/; SameSite=Lax; Max-Age=0');
  res.json({ ok: true });
});

app.get('/api/rooms', (req, res) => res.json({ rooms: db.prepare('SELECT id, name, number, code FROM rooms ORDER BY id').all() }));

app.get('/api/rooms/:id/qr', async (req, res) => {
  const room = db.prepare('SELECT id, name, number, code FROM rooms WHERE id = ?').get(req.params.id);
  if (!room) return res.status(404).json({ error: '이동실을 찾을 수 없습니다.' });
  const scanUrl = `${req.protocol}://${req.get('host')}/?student=1&code=${encodeURIComponent(room.code)}`;
  const dataUrl = await QRCode.toDataURL(scanUrl, { width: 900, margin: 2, color: { dark: '#19372a', light: '#ffffff' } });
  res.json({ room, scanUrl, dataUrl });
});

app.post('/api/rooms', requireTeacher, (req, res) => {
  const { name, number } = req.body || {};
  if (!name || !number) return res.status(400).json({ error: '이동실 이름과 번호를 입력해 주세요.' });
  const code = `LOG-${String(number).trim().toUpperCase()}`;
  try {
    const result = db.prepare('INSERT INTO rooms (name, number, code) VALUES (?, ?, ?)').run(String(name).trim(), String(number).trim(), code);
    res.json({ room: { id: result.lastInsertRowid, name: String(name).trim(), number: String(number).trim(), code } });
  } catch (error) { res.status(409).json({ error: '이미 등록된 실 번호입니다.' }); }
});

app.post('/api/requests', (req, res) => {
  const { studentName, roomCode } = req.body || {};
  const room = roomByCode(roomCode);
  if (!studentName || !room) return res.status(400).json({ error: '학생 이름과 이동실을 확인해 주세요.' });
  const result = db.prepare('INSERT INTO move_requests (student_name, room_id) VALUES (?, ?)').run(String(studentName).trim(), room.id);
  db.prepare('INSERT INTO notifications (kind, student_name, room_id, message) VALUES (?, ?, ?, ?)').run('request', String(studentName).trim(), room.id, `${String(studentName).trim()} 학생이 ${room.name}으로 이동 신청을 했어요.`);
  res.json({ requestId: result.lastInsertRowid, room: { name: room.name, code: room.code } });
});

app.post('/api/checkins', (req, res) => {
  const { studentName, roomCode } = req.body || {};
  const room = roomByCode(roomCode);
  if (!studentName || !room) return res.status(400).json({ error: '등록된 QR 코드가 아니에요. QR 카드의 코드를 다시 확인해 주세요.' });
  const cleanName = String(studentName).trim();
  const request = db.prepare(`SELECT * FROM move_requests WHERE student_name = ? AND room_id = ? AND status = 'requested' ORDER BY id DESC LIMIT 1`).get(cleanName, room.id);
  const now = isoNow();
  const visit = db.prepare('INSERT INTO visits (student_name, room_id, request_id, created_at) VALUES (?, ?, ?, ?)').run(cleanName, room.id, request?.id || null, now);
  if (request) db.prepare('UPDATE move_requests SET status = \'arrived\' WHERE id = ?').run(request.id);
  db.prepare('INSERT INTO notifications (kind, student_name, room_id, message, created_at) VALUES (?, ?, ?, ?, ?)').run('arrival', cleanName, room.id, `${cleanName} 학생이 ${room.name}에 도착했어요.`, now);
  res.json({ visitId: visit.lastInsertRowid, message: `${cleanName} 학생의 ${room.name} 도착 알림을 선생님에게 보냈어요.`, room: { name: room.name, code: room.code } });
});

app.get('/api/dashboard', requireTeacher, (req, res) => {
  const rooms = db.prepare('SELECT id, name, number, code FROM rooms ORDER BY id').all();
  const notifications = db.prepare(`SELECT n.id, n.kind, n.student_name AS studentName, n.message, n.is_read AS isRead, n.created_at AS createdAt, r.name AS roomName, r.code FROM notifications n JOIN rooms r ON r.id = n.room_id ORDER BY n.id DESC LIMIT 30`).all();
  const visits = db.prepare(`SELECT v.id, v.student_name AS studentName, v.created_at AS createdAt, r.name AS roomName, r.code FROM visits v JOIN rooms r ON r.id = v.room_id WHERE datetime(v.created_at) >= datetime('now', '-3 months') ORDER BY v.id DESC LIMIT 100`).all();
  const requests = db.prepare(`SELECT m.id, m.student_name AS studentName, m.status, m.created_at AS createdAt, r.name AS roomName, r.code FROM move_requests m JOIN rooms r ON r.id = m.room_id ORDER BY m.id DESC LIMIT 30`).all();
  const stats = db.prepare(`SELECT r.name, COUNT(v.id) AS count FROM rooms r LEFT JOIN visits v ON v.room_id = r.id AND datetime(v.created_at) >= datetime('now', '-3 months') GROUP BY r.id ORDER BY count DESC`).all();
  res.json({ rooms, notifications, visits, requests, stats });
});

app.post('/api/notifications/read', requireTeacher, (req, res) => { db.prepare('UPDATE notifications SET is_read = 1 WHERE id = ?').run(req.body?.id); res.json({ ok: true }); });

app.get('*', (req, res) => res.sendFile(path.join(ROOT, 'index.html')));
app.listen(PORT, () => console.log(`LoG고 server listening on http://localhost:${PORT}`));
