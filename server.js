const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const Database = require('better-sqlite3');
const axios = require('axios');
const { HttpsProxyAgent } = require('https-proxy-agent');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'datapick-secret-key-2024';
app.set('trust proxy', 1);

const db = new Database('database.db');
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL, points INTEGER DEFAULT 0, is_admin INTEGER DEFAULT 0,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );
  CREATE TABLE IF NOT EXISTS point_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, amount INTEGER,
    type TEXT, description TEXT, created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id)
  );
`);

const adminExists = db.prepare('SELECT id FROM users WHERE username = ?').get('admin');
if (!adminExists) {
  db.prepare('INSERT INTO users (username, password, points, is_admin) VALUES (?, ?, ?, ?)').run('admin', bcrypt.hashSync('admin1234', 10), 1000000, 1);
  console.log('관리자 계정 생성됨 - ID: admin, PW: admin1234, 포인트: 1,000,000');
}

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));

// ============ 프록시 ============
const PROXY_HOST = 'kr.decodo.com';
const PROXY_USER = 'spuqtp2czv';
const PROXY_PASS = '1voaShrNj_2f4V3hgB';
function getProxyAgent() {
  const port = 10001 + Math.floor(Math.random() * 10000); // 10001~20000 랜덤
  return new HttpsProxyAgent(`http://${PROXY_USER}:${PROXY_PASS}@${PROXY_HOST}:${port}`);
}

// ============ JWT ============
function requireLogin(req, res, next) {
  const token = req.cookies.token || req.headers.authorization?.replace('Bearer ', '');
  if (!token) return res.status(401).json({ error: '로그인이 필요합니다.' });
  try { req.user = jwt.verify(token, JWT_SECRET); next(); }
  catch (e) { return res.status(401).json({ error: '토큰 만료' }); }
}

// ============ 인증 ============
app.post('/api/login', (req, res) => {
  const { username, password } = req.body;
  const user = db.prepare('SELECT * FROM users WHERE username = ?').get(username);
  if (!user || !bcrypt.compareSync(password, user.password))
    return res.status(401).json({ error: '아이디 또는 비밀번호가 올바르지 않습니다.' });
  const token = jwt.sign({ userId: user.id, username: user.username, isAdmin: user.is_admin }, JWT_SECRET, { expiresIn: '7d' });
  res.cookie('token', token, { httpOnly: true, maxAge: 7 * 86400000 });
  res.json({ success: true, token, user: { id: user.id, username: user.username, points: user.points, isAdmin: user.is_admin } });
});

app.post('/api/register', (req, res) => {
  const { username, password } = req.body;
  if (!username || !password || username.length < 4 || password.length < 4)
    return res.status(400).json({ error: '아이디와 비밀번호는 4자 이상' });
  if (db.prepare('SELECT id FROM users WHERE username = ?').get(username))
    return res.status(400).json({ error: '이미 존재하는 아이디' });
  db.prepare('INSERT INTO users (username, password, points) VALUES (?, ?, ?)').run(username, bcrypt.hashSync(password, 10), 100);
  res.json({ success: true });
});

app.get('/api/me', requireLogin, (req, res) => {
  const user = db.prepare('SELECT id, username, points, is_admin FROM users WHERE id = ?').get(req.user.userId);
  if (!user) return res.status(401).json({ error: '사용자 없음' });
  res.json({ user: { id: user.id, username: user.username, points: user.points, isAdmin: user.is_admin } });
});

app.post('/api/logout', (req, res) => { res.clearCookie('token'); res.json({ success: true }); });

// ============ 크롤링 ============
app.post('/api/extract/place', requireLogin, async (req, res) => {
  const { keyword, startRank, endRank } = req.body;
  if (!keyword) return res.status(400).json({ error: '키워드를 입력해주세요.' });
  const sr = parseInt(startRank) || 1;
  const er = parseInt(endRank) || 75;
  const count = er - sr + 1;
  const user = db.prepare('SELECT points FROM users WHERE id = ?').get(req.user.userId);
  if (user.points < count) return res.status(400).json({ error: `포인트 부족 (보유: ${user.points}P, 필요: ${count}P)` });

  try {
    console.log(`\n========== 크롤링: ${keyword} (${sr}~${er}위) ==========`);

    // 1단계: 모바일 검색 → Place ID 수집
    const agent = getProxyAgent();
    const searchRes = await axios.get(
      `https://m.map.naver.com/search2/search.naver?query=${encodeURIComponent(keyword)}&sm=hty&style=v5`,
      { httpsAgent: agent, timeout: 30000, headers: {
        'User-Agent': 'Mozilla/5.0 (iPhone; CPU iPhone OS 16_0 like Mac OS X) AppleWebKit/605.1.15',
        'Accept': 'text/html', 'Accept-Language': 'ko-KR,ko;q=0.9',
      }}
    );
    const html = searchRes.data;
    console.log(`검색 HTML: ${html.length}자`);

    const placeIds = [];
    for (const p of [/place\/(\d{8,})/gi, /sid[=:][\s"']*(\d{8,})/gi, /"id"\s*:\s*"?(\d{8,})"?/gi]) {
      let m; while ((m = p.exec(html)) !== null) {
        if (!placeIds.includes(m[1])) placeIds.push(m[1]);
      }
    }
    console.log(`Place ID: ${placeIds.length}개`);
    if (!placeIds.length) return res.status(400).json({ error: '검색 결과 없음' });

    // 2단계: 각 Place 상세 페이지 (PC 버전) + 실패 시 재시도
    const targetIds = placeIds.slice(sr - 1, Math.min(er, placeIds.length));
    const results = [];
    const BATCH = 3; // 5→3으로 줄여서 속도 조절
    const SKIP = ['네이버', 'naver', 'NAVER', '검색', '지도', '플레이스', 'place', 'map'];
    
    // User-Agent 랜덤 돌리기
    const UAs = [
      'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
      'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36',
      'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
      'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15',
      'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0',
      'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    ];

    async function fetchPlace(pid, rank, retry = 0) {
      try {
        const da = getProxyAgent();
        const ua = UAs[Math.floor(Math.random() * UAs.length)];
        const d = (await axios.get(`https://pcmap.place.naver.com/place/${pid}/home`, {
          httpsAgent: da, timeout: 15000,
          headers: {
            'User-Agent': ua,
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'ko-KR,ko;q=0.9,en-US;q=0.8',
            'Accept-Encoding': 'gzip, deflate, br',
            'Connection': 'keep-alive',
            'Referer': 'https://map.naver.com/',
          }
        })).data;

        let name = '', tel = '', address = '', category = '';

        // 업체명
        for (const nm of d.matchAll(/"name"\s*:\s*"([^"]{2,60})"/g)) {
          const n = nm[1];
          if (SKIP.some(s => n.toLowerCase().includes(s.toLowerCase())) || n.startsWith('http') || n.startsWith('/')) continue;
          name = n; break;
        }

        // 전화번호
        const tm = d.match(/"(?:phone|tel|virtualPhone|virtualTel)"\s*:\s*"([0-9\-]+)"/) || d.match(/href="tel:([^"]+)"/);
        if (tm) tel = tm[1];

        // 주소
        const am = d.match(/"roadAddress"\s*:\s*"([^"]+)"/) || d.match(/"address"\s*:\s*"([^"]{10,})"/);
        if (am) address = am[1];

        // 카테고리
        const ca = d.match(/"category"\s*:\s*\[([^\]]+)\]/);
        if (ca) { try { category = JSON.parse('[' + ca[1] + ']').join(' > '); } catch(e) {} }
        if (!category) { const cm = d.match(/"category"\s*:\s*"([^"]+)"/); if (cm) category = cm[1]; }

        // 폴백: og:title
        if (!name) {
          const og = d.match(/<meta\s+property="og:title"\s+content="([^"]+)"/);
          if (og) { const t = og[1].replace(/\s*[:·\-|].*/g, '').trim(); if (!SKIP.some(s => t.includes(s))) name = t; }
        }

        // 이름 못 찾았으면 재시도
        if (!name && retry < 3) {
          await new Promise(r => setTimeout(r, 1000 + retry * 1000));
          return fetchPlace(pid, rank, retry + 1);
        }

        return { rank, name, tel, address, category, placeId: pid };
      } catch (e) {
        const is429 = e.response?.status === 429;
        if (retry < 3) {
          // 429면 길게 대기, 그 외는 짧게
          const wait = is429 ? 3000 + retry * 2000 : 1000 + retry * 500;
          console.log(`  ${rank}위 ${is429 ? '429 차단' : '에러'} → ${(wait/1000).toFixed(1)}초 후 재시도 ${retry + 1}/3`);
          await new Promise(r => setTimeout(r, wait));
          return fetchPlace(pid, rank, retry + 1);
        }
        return { rank, name: '', tel: '', address: '', category: '', placeId: pid };
      }
    }

    for (let i = 0; i < targetIds.length; i += BATCH) {
      const batch = targetIds.slice(i, i + BATCH);
      const br = await Promise.all(batch.map((pid, idx) => fetchPlace(pid, sr + i + idx)));
      results.push(...br);
      
      const done = Math.min(i + BATCH, targetIds.length);
      const okSoFar = results.filter(r => r.name).length;
      console.log(`진행: ${done}/${targetIds.length} (성공: ${okSoFar})`);
      
      // 배치 간 랜덤 딜레이 (0.5~1.5초)
      if (i + BATCH < targetIds.length) {
        await new Promise(r => setTimeout(r, 500 + Math.floor(Math.random() * 1000)));
      }
    }

    // 포인트: 실제 추출 성공건만 차감
    const successResults = results.filter(r => r.name);
    const used = successResults.length;
    const newPts = user.points - used;
    db.prepare('UPDATE users SET points = ? WHERE id = ?').run(newPts, req.user.userId);
    db.prepare('INSERT INTO point_history (user_id, amount, type, description) VALUES (?, ?, ?, ?)').run(
      req.user.userId, -used, 'use', `플레이스: ${keyword} (성공 ${used}/${results.length}건)`);
    console.log(`완료: ${results.length}건 중 성공 ${used}건, ${used}P 차감\n`);
    res.json({ success: true, data: results, usedPoints: used, remainingPoints: newPts });
  } catch (error) {
    console.error('크롤링 에러:', error.message);
    res.status(500).json({ error: '데이터 추출 오류: ' + error.message });
  }
});

// ============ 포인트/관리자 ============
app.get('/api/history/points', requireLogin, (req, res) => {
  res.json(db.prepare('SELECT * FROM point_history WHERE user_id = ? ORDER BY created_at DESC LIMIT 50').all(req.user.userId));
});
app.get('/api/admin/users', requireLogin, (req, res) => {
  if (!req.user.isAdmin) return res.status(403).json({ error: '권한 없음' });
  res.json(db.prepare('SELECT id, username, points, is_admin, created_at FROM users ORDER BY created_at DESC').all());
});
app.post('/api/admin/points', requireLogin, (req, res) => {
  if (!req.user.isAdmin) return res.status(403).json({ error: '권한 없음' });
  const { userId, amount } = req.body;
  const u = db.prepare('SELECT * FROM users WHERE id = ?').get(userId);
  if (!u) return res.status(404).json({ error: '사용자 없음' });
  const np = u.points + amount;
  if (np < 0) return res.status(400).json({ error: '포인트 부족' });
  db.prepare('UPDATE users SET points = ? WHERE id = ?').run(np, userId);
  db.prepare('INSERT INTO point_history (user_id, amount, type, description) VALUES (?, ?, ?, ?)').run(
    userId, amount, amount > 0 ? 'charge' : 'deduct', amount > 0 ? '관리자 지급' : '관리자 차감');
  res.json({ success: true, newPoints: np });
});

app.listen(PORT, () => console.log(`서버: http://localhost:${PORT}`));
