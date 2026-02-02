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
const JWT_SECRET = process.env.JWT_SECRET || 'datapick-secret-2024';

app.set('trust proxy', 1);

const db = new Database('database.db');

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    points INTEGER DEFAULT 0,
    is_admin INTEGER DEFAULT 0,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );
  CREATE TABLE IF NOT EXISTS point_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    amount INTEGER,
    type TEXT,
    description TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );
`);

const adminExists = db.prepare('SELECT id FROM users WHERE username = ?').get('admin');
if (!adminExists) {
  const hashedPw = bcrypt.hashSync('admin1234', 10);
  db.prepare('INSERT INTO users (username, password, points, is_admin) VALUES (?, ?, ?, ?)').run('admin', hashedPw, 1000000, 1);
  console.log('관리자 계정 생성됨 - ID: admin, PW: admin1234');
}

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));

// ============ 프록시 (Decodo 한국) ============
const PROXY_HOST = 'kr.decodo.com';
const PROXY_USER = 'spuqtp2czv';
const PROXY_PASS = '1voaShrNj_2f4V3hgB';

let proxyIdx = 0;
function getProxyAgent() {
  const port = 10001 + (proxyIdx % 1000);
  proxyIdx++;
  return new HttpsProxyAgent(`http://${PROXY_USER}:${PROXY_PASS}@${PROXY_HOST}:${port}`);
}

// ============ JWT ============
function requireLogin(req, res, next) {
  const token = req.cookies.token || req.headers.authorization?.replace('Bearer ', '');
  if (!token) return res.status(401).json({ error: '로그인 필요' });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch (e) {
    return res.status(401).json({ error: '토큰 만료' });
  }
}

app.post('/api/login', (req, res) => {
  const { username, password } = req.body;
  const user = db.prepare('SELECT * FROM users WHERE username = ?').get(username);
  if (!user || !bcrypt.compareSync(password, user.password))
    return res.status(401).json({ error: '아이디 또는 비밀번호 오류' });
  const token = jwt.sign({ userId: user.id, username: user.username, isAdmin: user.is_admin }, JWT_SECRET, { expiresIn: '7d' });
  res.cookie('token', token, { httpOnly: true, maxAge: 7 * 86400000 });
  res.json({ success: true, token, user: { id: user.id, username: user.username, points: user.points, isAdmin: user.is_admin } });
});

app.get('/api/me', requireLogin, (req, res) => {
  const user = db.prepare('SELECT id, username, points, is_admin FROM users WHERE id = ?').get(req.user.userId);
  res.json({ user });
});

app.post('/api/logout', (req, res) => {
  res.clearCookie('token');
  res.json({ success: true });
});

// ============ 크롤링 ============
app.post('/api/extract/place', requireLogin, async (req, res) => {
  const { keyword } = req.body;
  if (!keyword) return res.status(400).json({ error: '키워드를 입력해주세요.' });

  const user = db.prepare('SELECT points FROM users WHERE id = ?').get(req.user.userId);
  if (user.points < 75) return res.status(400).json({ error: `포인트 부족 (보유: ${user.points}P, 필요: 75P)` });

  try {
    console.log(`\n크롤링: ${keyword} (1~75위)`);

    // 1단계: 모바일 검색 → Place ID 수집
    const agent = getProxyAgent();
    const searchUrl = `https://m.map.naver.com/search2/search.naver?query=${encodeURIComponent(keyword)}&sm=hty&style=v5`;

    console.log('모바일 검색 요청...');
    const searchRes = await axios.get(searchUrl, {
      httpsAgent: agent,
      timeout: 30000,
      headers: {
        'User-Agent': 'Mozilla/5.0 (iPhone; CPU iPhone OS 16_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.0 Mobile/15E148 Safari/604.1',
        'Accept': 'text/html,application/xhtml+xml',
        'Accept-Language': 'ko-KR,ko;q=0.9',
      }
    });

    const html = searchRes.data;
    console.log(`HTML: ${html.length}자`);

    // Place ID 추출
    const placeIds = [];
    const patterns = [/place\/(\d{8,})/gi, /"id"\s*:\s*"?(\d{8,})"?/gi, /sid[=:][\s"']*(\d{8,})/gi];
    for (const p of patterns) {
      let m;
      while ((m = p.exec(html)) !== null) {
        if (!placeIds.includes(m[1])) placeIds.push(m[1]);
      }
    }

    console.log(`Place ID: ${placeIds.length}개`);
    if (placeIds.length === 0) return res.status(400).json({ error: '검색 결과 없음' });

    // 2단계: 상세 정보 수집 (5개씩 병렬)
    const targetIds = placeIds.slice(0, 75);
    const results = [];

    for (let i = 0; i < targetIds.length; i += 5) {
      const batch = targetIds.slice(i, i + 5);
      const batchResults = await Promise.all(batch.map(async (pid, idx) => {
        const rank = i + idx + 1;
        try {
          const da = getProxyAgent();
          const dRes = await axios.get(`https://m.place.naver.com/place/${pid}/home`, {
            httpsAgent: da,
            timeout: 15000,
            headers: { 'User-Agent': 'Mozilla/5.0 (iPhone; CPU iPhone OS 16_0 like Mac OS X) AppleWebKit/605.1.15' }
          });

          const dHtml = dRes.data;
          let name = '', tel = '', address = '', category = '';

          // Apollo State
          const am = dHtml.match(/__APOLLO_STATE__\s*=\s*({.+?});?\s*<\/script>/s);
          if (am) {
            try {
              const ad = JSON.parse(am[1]);
              for (const k of Object.keys(ad)) {
                const o = ad[k];
                if (o && typeof o === 'object') {
                  if (!name && o.name && typeof o.name === 'string') name = o.name;
                  if (!address && (o.roadAddress || o.address)) address = o.roadAddress || o.address;
                  if (!category && o.category) category = Array.isArray(o.category) ? o.category.join(' > ') : o.category;
                  if (!tel) tel = o.phone || o.tel || o.virtualPhone || '';
                }
              }
            } catch (e) {}
          }

          // 백업 추출
          if (!tel) {
            for (const tp of [/"phone":"([^"]+)"/, /"tel":"([^"]+)"/, /href="tel:([^"]+)"/]) {
              const tm = dHtml.match(tp);
              if (tm) { tel = tm[1]; break; }
            }
          }
          if (!name) {
            const nm = dHtml.match(/<meta\s+property="og:title"\s+content="([^"]+)"/);
            if (nm) name = nm[1].split(':')[0].split('-')[0].trim();
          }

          return { rank, name, tel, address, category, placeId: pid };
        } catch (e) {
          return { rank, name: '', tel: '', address: '', category: '', placeId: pid };
        }
      }));

      results.push(...batchResults);
      console.log(`진행: ${Math.min(i + 5, targetIds.length)}/${targetIds.length}`);
      if (i + 5 < targetIds.length) await new Promise(r => setTimeout(r, 200));
    }

    // 포인트 차감
    const used = results.length;
    const newPts = user.points - used;
    db.prepare('UPDATE users SET points = ? WHERE id = ?').run(newPts, req.user.userId);
    db.prepare('INSERT INTO point_history (user_id, amount, type, description) VALUES (?, ?, ?, ?)').run(req.user.userId, -used, 'use', `${keyword} (${used}건)`);

    const ok = results.filter(r => r.name).length;
    console.log(`완료: ${results.length}건 (성공: ${ok}건)\n`);

    res.json({ success: true, data: results, usedPoints: used, remainingPoints: newPts });
  } catch (error) {
    console.error('크롤링 에러:', error.message);
    res.status(500).json({ error: error.message });
  }
});

app.listen(PORT, () => console.log(`서버: http://localhost:${PORT}`));
