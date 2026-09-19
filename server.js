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
  CREATE TABLE IF NOT EXISTS sessions (
    token TEXT PRIMARY KEY,
    teacher_id INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    FOREIGN KEY (teacher_id) REFERENCES teachers(id)
  );
`);

const ensureColumn = (table, column, definition = 'TEXT') => {
  const columns = db.prepare(`PRAGMA table_info(${table})`).all();
  if (!columns.some((item) => item.name === column)) db.exec(`ALTER TABLE ${table} ADD COLUMN ${column} ${definition}`);
};
ensureColumn('move_requests', 'student_id');
ensureColumn('move_requests', 'student_grade');
ensureColumn('move_requests', 'student_class');
ensureColumn('move_requests', 'period');
ensureColumn('visits', 'student_id');
ensureColumn('visits', 'student_grade');
ensureColumn('visits', 'student_class');
ensureColumn('visits', 'period');
ensureColumn('visits', 'confirmed', 'INTEGER NOT NULL DEFAULT 0');
ensureColumn('notifications', 'student_id');
ensureColumn('notifications', 'period');
ensureColumn('rooms', 'qr_token');
ensureColumn('rooms', 'qr_day');
db.prepare("UPDATE move_requests SET status = 'pending' WHERE status = 'requested'").run();

const seedTeacher = db.prepare('SELECT id FROM teachers WHERE email = ?').get('teacher@loggo.local');
if (!seedTeacher) {
  db.prepare('INSERT INTO teachers (name, email, password_hash) VALUES (?, ?, ?)').run('야자 감독 선생님', 'teacher@loggo.local', bcrypt.hashSync('loggo2026', 10));
}
const roomSeeds = [['1번 실습실', '101'], ['2번 실습실', '102'], ['3번 실습실', '103'], ['창의 융합실', '201']];
const insertRoom = db.prepare('INSERT OR IGNORE INTO rooms (name, number, code) VALUES (?, ?, ?)');
roomSeeds.forEach(([name, number]) => insertRoom.run(name, number, `LOG-${number}`));

const createSession = (teacherId) => { const token = crypto.randomBytes(32).toString('hex'); db.prepare('INSERT INTO sessions (token, teacher_id, expires_at) VALUES (?, ?, ?)').run(token, teacherId, Date.now() + 1000 * 60 * 60 * 12); return token; };
const getSession = (req) => {
  const token = req.headers.cookie?.match(/(?:^|; )loggo_session=([^;]+)/)?.[1];
  if (!token) return null;
  const session = db.prepare('SELECT teacher_id AS teacherId, expires_at AS expiresAt FROM sessions WHERE token = ?').get(token);
  if (!session) return null;
  if (session.expiresAt < Date.now()) { db.prepare('DELETE FROM sessions WHERE token = ?').run(token); return null; }
  return session;
};
const requireTeacher = (req, res, next) => { const session = getSession(req); if (!session) return res.status(401).json({ error: '로그인이 필요합니다.' }); req.teacher = session; next(); };
const isoNow = () => new Date().toISOString();
const roomByCode = (code) => db.prepare('SELECT * FROM rooms WHERE code = ?').get(String(code || '').trim().toUpperCase());
const todayKey = () => new Date().toISOString().slice(0, 10);
const dailyRoomToken = (room) => {
  const day = todayKey();
  if (!room.qr_token || room.qr_day !== day) {
    const token = crypto.randomBytes(18).toString('hex');
    db.prepare('UPDATE rooms SET qr_token = ?, qr_day = ? WHERE id = ?').run(token, day, room.id);
    room.qr_token = token;
    room.qr_day = day;
  }
  return room.qr_token;
};

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
  if (token) db.prepare('DELETE FROM sessions WHERE token = ?').run(token);
  res.setHeader('Set-Cookie', 'loggo_session=; HttpOnly; Path=/; SameSite=Lax; Max-Age=0');
  res.json({ ok: true });
});

app.get('/api/rooms', (req, res) => res.json({ rooms: db.prepare('SELECT id, name, number, code FROM rooms ORDER BY id').all() }));

app.get('/api/rooms/:id/qr', async (req, res) => {
  const room = db.prepare('SELECT id, name, number, code, qr_token, qr_day FROM rooms WHERE id = ?').get(req.params.id);
  if (!room) return res.status(404).json({ error: '이동실을 찾을 수 없습니다.' });
  const token = dailyRoomToken(room);
  const publicHost = req.get('x-forwarded-host') || req.get('host');
  const publicProtocol = (req.get('x-forwarded-proto') || req.protocol).split(',')[0].trim();
  const scanUrl = `${publicProtocol}://${publicHost}/?student=1&code=${encodeURIComponent(room.code)}&token=${encodeURIComponent(token)}`;
  const dataUrl = await QRCode.toDataURL(scanUrl, { width: 900, margin: 2, color: { dark: '#702542', light: '#ffffff' } });
  res.json({ room, scanUrl, dataUrl, qrDay: todayKey() });
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
  const { studentName, studentId, period, roomCode } = req.body || {};
  const room = roomByCode(roomCode);
  if (!studentName || !studentId || !['10', '11'].includes(String(period)) || !room) return res.status(400).json({ error: '교시, 이름, 학번, 이동실을 모두 확인해 주세요.' });
  const cleanName = String(studentName).trim();
  const cleanId = String(studentId).trim();
  const cleanPeriod = String(period);
  const result = db.prepare('INSERT INTO move_requests (student_name, student_id, period, room_id, status) VALUES (?, ?, ?, ?, ?)').run(cleanName, cleanId, cleanPeriod, room.id, 'pending');
  db.prepare('INSERT INTO notifications (kind, student_name, student_id, period, room_id, message) VALUES (?, ?, ?, ?, ?, ?)').run('request', cleanName, cleanId, cleanPeriod, room.id, `${cleanName}(${cleanId}) 학생이 ${cleanPeriod}교시 ${room.name}으로 이동 신청을 했어요.`);
  res.json({ requestId: result.lastInsertRowid, room: { name: room.name, code: room.code } });
});

app.get('/api/requests/:id', (req, res) => {
  const request = db.prepare(`SELECT m.id, m.student_grade AS studentGrade, m.student_class AS studentClass, m.student_name AS studentName, m.student_id AS studentId, m.period, m.status, m.room_id AS roomId, r.name AS roomName, r.code FROM move_requests m JOIN rooms r ON r.id = m.room_id WHERE m.id = ?`).get(req.params.id);
  if (!request) return res.status(404).json({ error: '신청 정보를 찾을 수 없습니다.' });
  res.json({ request });
});

app.post('/api/checkins', (req, res) => {
  const { studentName, studentId, period, roomCode, qrToken } = req.body || {};
  const room = roomByCode(roomCode);
  if (!studentName || !studentId || !['10', '11'].includes(String(period)) || !room || !qrToken) return res.status(400).json({ error: '실에 붙은 오늘 QR을 스마트폰 카메라로 찍어 인증 페이지를 열어 주세요.' });
  if (dailyRoomToken(room) !== String(qrToken)) return res.status(403).json({ error: '만료되었거나 다른 날의 QR입니다. 오늘 출력된 QR을 다시 찍어 주세요.' });
  const cleanName = String(studentName).trim();
  const cleanId = String(studentId).trim();
  const cleanPeriod = String(period);
  const identityRequest = db.prepare(`SELECT * FROM move_requests WHERE student_name = ? AND student_id = ? AND period = ? AND status IN ('pending', 'approved') ORDER BY id DESC LIMIT 1`).get(cleanName, cleanId, cleanPeriod);
  if (!identityRequest) return res.status(403).json({ error: '신청한 학생 정보와 일치하는 승인 기록이 없습니다.' });
  if (identityRequest.room_id !== room.id) return res.status(403).json({ error: `신청한 실과 다릅니다. 신청한 실: ${db.prepare('SELECT name FROM rooms WHERE id = ?').get(identityRequest.room_id).name}` });
  if (identityRequest.status !== 'approved') return res.status(403).json({ error: '아직 선생님이 이동 신청을 승인하지 않았습니다.' });
  const now = isoNow();
  const visit = db.prepare('INSERT INTO visits (student_name, student_id, period, room_id, request_id, created_at, confirmed) VALUES (?, ?, ?, ?, ?, ?, 0)').run(cleanName, cleanId, cleanPeriod, room.id, identityRequest.id, now);
  db.prepare('UPDATE move_requests SET status = \'arrived\' WHERE id = ?').run(identityRequest.id);
  db.prepare('INSERT INTO notifications (kind, student_name, student_id, period, room_id, message, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)').run('arrival', cleanName, cleanId, cleanPeriod, room.id, `${cleanName}(${cleanId}) 학생이 ${cleanPeriod}교시 ${room.name}에 도착했어요.`, now);
  res.json({ visitId: visit.lastInsertRowid, message: `${cleanName} 학생의 ${room.name} 도착 알림을 선생님에게 보냈어요.`, room: { name: room.name, code: room.code } });
});

app.get('/api/dashboard', requireTeacher, (req, res) => {
  const rooms = db.prepare('SELECT id, name, number, code FROM rooms ORDER BY id').all();
  const notifications = db.prepare(`SELECT n.id, n.kind, n.student_name AS studentName, n.student_id AS studentId, n.period, n.message, n.is_read AS isRead, n.created_at AS createdAt, r.name AS roomName, r.code FROM notifications n JOIN rooms r ON r.id = n.room_id ORDER BY n.id DESC LIMIT 30`).all();
  const visits = db.prepare(`SELECT v.id, v.student_grade AS studentGrade, v.student_class AS studentClass, v.student_name AS studentName, v.student_id AS studentId, v.period, v.confirmed, v.created_at AS createdAt, r.name AS roomName, r.code FROM visits v JOIN rooms r ON r.id = v.room_id WHERE datetime(v.created_at) >= datetime('now', '-3 months') ORDER BY v.id DESC LIMIT 100`).all();
  const requests = db.prepare(`SELECT m.id, m.student_grade AS studentGrade, m.student_class AS studentClass, m.student_name AS studentName, m.student_id AS studentId, m.period, m.status, m.created_at AS createdAt, r.name AS roomName, r.code FROM move_requests m JOIN rooms r ON r.id = m.room_id ORDER BY m.id DESC LIMIT 30`).all();
  const stats = db.prepare(`SELECT r.name, COUNT(v.id) AS count FROM rooms r LEFT JOIN visits v ON v.room_id = r.id AND datetime(v.created_at) >= datetime('now', '-3 months') GROUP BY r.id ORDER BY count DESC`).all();
  res.json({ rooms, notifications, visits, requests, stats });
});

app.post('/api/requests/:id/status', requireTeacher, (req, res) => {
  const status = String(req.body?.status || '');
  if (!['approved', 'rejected'].includes(status)) return res.status(400).json({ error: '올바른 승인 상태가 아닙니다.' });
  const result = db.prepare(`UPDATE move_requests SET status = ? WHERE id = ? AND status IN ('pending', 'requested')`).run(status, req.params.id);
  if (!result.changes) return res.status(404).json({ error: '대기 중인 신청을 찾을 수 없습니다.' });
  res.json({ ok: true, status });
});

app.post('/api/visits/:id/confirm', requireTeacher, (req, res) => {
  const result = db.prepare('UPDATE visits SET confirmed = 1 WHERE id = ?').run(req.params.id);
  if (!result.changes) return res.status(404).json({ error: '도착 기록을 찾을 수 없습니다.' });
  res.json({ ok: true });
});

app.delete('/api/admin/records', requireTeacher, (req, res) => {
  const clearRecords = db.transaction(() => {
    db.prepare('DELETE FROM notifications').run();
    db.prepare('DELETE FROM visits').run();
    db.prepare('DELETE FROM move_requests').run();
  });
  clearRecords();
  res.json({ ok: true });
});

app.post('/api/notifications/read', requireTeacher, (req, res) => { db.prepare('UPDATE notifications SET is_read = 1 WHERE id = ?').run(req.body?.id); res.json({ ok: true }); });

app.get('*', (req, res) => res.sendFile(path.join(ROOT, 'index.html')));
app.listen(PORT, () => console.log(`LoG고 server listening on http://localhost:${PORT}`));
