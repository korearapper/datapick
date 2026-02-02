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

// ============ DB ============
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
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id)
  );
`);

const adminExists = db.prepare('SELECT id FROM users WHERE username = ?').get('admin');
if (!adminExists) {
  const hashedPw = bcrypt.hashSync('admin1234', 10);
  db.prepare('INSERT INTO users (username, password, points, is_admin) VALUES (?, ?, ?, ?)').run('admin', hashedPw, 1000000, 1);
  console.log('관리자 계정 생성됨 - ID: admin, PW: admin1234, 포인트: 1,000,000');
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

// ============ JWT 인증 ============
function requireLogin(req, res, next) {
  const token = req.cookies.token || req.headers.authorization?.replace('Bearer ', '');
  if (!token) return res.status(401).json({ error: '로그인이 필요합니다.' });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch (e) {
    return res.status(401).json({ error: '유효하지 않은 토큰입니다.' });
  }
}

// ============ 인증 API ============
app.post('/api/login', (req, res) => {
  const { username, password } = req.body;
  const user = db.prepare('SELECT * FROM users WHERE username = ?').get(username);
  if (!user || !bcrypt.compareSync(password, user.password)) {
    return res.status(401).json({ error: '아이디 또는 비밀번호가 올바르지 않습니다.' });
  }
  const token = jwt.sign({ userId: user.id, username: user.username, isAdmin: user.is_admin }, JWT_SECRET, { expiresIn: '7d' });
  res.cookie('token', token, { httpOnly: true, maxAge: 7 * 24 * 60 * 60 * 1000 });
  res.json({ success: true, token, user: { id: user.id, username: user.username, points: user.points, isAdmin: user.is_admin } });
});

app.post('/api/register', (req, res) => {
  const { username, password } = req.body;
  if (!username || !password || username.length < 4 || password.length < 4) {
    return res.status(400).json({ error: '아이디와 비밀번호는 4자 이상이어야 합니다.' });
  }
  const exists = db.prepare('SELECT id FROM users WHERE username = ?').get(username);
  if (exists) return res.status(400).json({ error: '이미 존재하는 아이디입니다.' });
  const hashedPw = bcrypt.hashSync(password, 10);
  db.prepare('INSERT INTO users (username, password, points) VALUES (?, ?, ?)').run(username, hashedPw, 100);
  res.json({ success: true });
});

app.get('/api/me', requireLogin, (req, res) => {
  const user = db.prepare('SELECT id, username, points, is_admin FROM users WHERE id = ?').get(req.user.userId);
  if (!user) return res.status(401).json({ error: '사용자를 찾을 수 없습니다.' });
  res.json({ user: { id: user.id, username: user.username, points: user.points, isAdmin: user.is_admin } });
});

app.post('/api/logout', (req, res) => {
  res.clearCookie('token');
  res.json({ success: true });
});

// ============ 플레이스 크롤링 API ============
app.post('/api/extract/place', requireLogin, async (req, res) => {
  const { keyword, startRank, endRank } = req.body;
  if (!keyword) return res.status(400).json({ error: '키워드를 입력해주세요.' });

  const sr = parseInt(startRank) || 1;
  const er = parseInt(endRank) || 75;
  const count = er - sr + 1;

  const user = db.prepare('SELECT points FROM users WHERE id = ?').get(req.user.userId);
  if (user.points < count) {
    return res.status(400).json({ error: `포인트 부족 (보유: ${user.points}P, 필요: ${count}P)` });
  }

  try {
    console.log(`\n========================================`);
    console.log(`크롤링 시작: ${keyword}, ${sr}~${er}위`);
    console.log(`========================================`);

    // 1단계: 모바일 검색 페이지에서 Place ID 수집
    const agent = getProxyAgent();
    const searchUrl = `https://m.map.naver.com/search2/search.naver?query=${encodeURIComponent(keyword)}&sm=hty&style=v5`;

    console.log('[1단계] 모바일 검색 요청...');
    const searchRes = await axios.get(searchUrl, {
      httpsAgent: agent,
      timeout: 30000,
      headers: {
        'User-Agent': 'Mozilla/5.0 (iPhone; CPU iPhone OS 16_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.0 Mobile/15E148 Safari/604.1',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        'Accept-Language': 'ko-KR,ko;q=0.9',
      }
    });

    const html = searchRes.data;
    console.log(`HTML 응답: ${html.length}자`);

    // Place ID 추출
    const placeIds = [];
    const patterns = [/place\/(\d{8,})/gi, /"id"\s*:\s*"?(\d{8,})"?/gi, /sid[=:][\s"']*(\d{8,})/gi, /data-id="(\d{8,})"/gi];
    for (const p of patterns) {
      let m;
      while ((m = p.exec(html)) !== null) {
        if (!placeIds.includes(m[1])) placeIds.push(m[1]);
      }
    }

    console.log(`Place ID 수집: ${placeIds.length}개`);
    if (placeIds.length === 0) return res.status(400).json({ error: '검색 결과를 찾을 수 없습니다.' });

    // 대상 범위
    const actualEnd = Math.min(er, placeIds.length);
    const targetIds = placeIds.slice(sr - 1, actualEnd);
    if (targetIds.length === 0) {
      return res.status(400).json({ error: `검색 결과가 ${placeIds.length}개뿐입니다.` });
    }

    console.log(`[2단계] 상세 정보 수집: ${targetIds.length}건`);

    // 2단계: 상세 페이지에서 정보 추출 (5개씩 병렬)
    const results = [];
    const BATCH = 5;

    for (let i = 0; i < targetIds.length; i += BATCH) {
      const batch = targetIds.slice(i, i + BATCH);
      const batchResults = await Promise.all(batch.map(async (pid, idx) => {
        const rank = sr + i + idx;
        try {
          const da = getProxyAgent();
          const dRes = await axios.get(`https://m.place.naver.com/place/${pid}/home`, {
            httpsAgent: da, timeout: 15000,
            headers: { 'User-Agent': 'Mozilla/5.0 (iPhone; CPU iPhone OS 16_0 like Mac OS X) AppleWebKit/605.1.15' }
          });
          const dHtml = dRes.data;
          let name = '', tel = '', address = '', category = '';

          // 방법1: __APOLLO_STATE__ 파싱
          const am = dHtml.match(/__APOLLO_STATE__\s*=\s*({.+?});?\s*<\/script>/s);
          if (am) {
            try {
              const ad = JSON.parse(am[1]);
              for (const k of Object.keys(ad)) {
                const o = ad[k];
                if (!o || typeof o !== 'object') continue;
                
                // PlaceBase 또는 메인 엔트리 찾기
                if (k.startsWith('PlaceSummary') || k.startsWith('PlaceBase') || k === 'ROOT_QUERY') continue;
                
                // 이름: name 필드가 문자열이고 2자 이상
                if (!name && o.name && typeof o.name === 'string' && o.name.length >= 2 && !o.name.startsWith('http')) {
                  name = o.name;
                }
                // 주소
                if (!address) {
                  if (o.roadAddress && typeof o.roadAddress === 'string') address = o.roadAddress;
                  else if (o.address && typeof o.address === 'string' && o.address.length > 5) address = o.address;
                }
                // 카테고리
                if (!category) {
                  if (Array.isArray(o.category) && o.category.length > 0) category = o.category.join(' > ');
                  else if (typeof o.category === 'string' && o.category.length > 0) category = o.category;
                  else if (Array.isArray(o.categoryPath) && o.categoryPath.length > 0) category = o.categoryPath.join(' > ');
                }
                // 전화
                if (!tel) {
                  tel = o.phone || o.tel || o.virtualPhone || o.virtualTel || o.phoneNumber || '';
                }
              }
            } catch (e) {}
          }

          // 방법2: JSON-LD (schema.org)
          if (!name) {
            const ldMatch = dHtml.match(/<script type="application\/ld\+json">([\s\S]*?)<\/script>/);
            if (ldMatch) {
              try {
                const ld = JSON.parse(ldMatch[1]);
                if (!name && ld.name) name = ld.name;
                if (!address && ld.address) address = typeof ld.address === 'string' ? ld.address : (ld.address.streetAddress || '');
                if (!tel && ld.telephone) tel = ld.telephone;
              } catch (e) {}
            }
          }

          // 방법3: og:title
          if (!name) {
            const ogMatch = dHtml.match(/<meta\s+property="og:title"\s+content="([^"]+)"/);
            if (ogMatch) {
              name = ogMatch[1].replace(/\s*[:·\-|].*/g, '').trim();
            }
          }
          // 방법4: <title> 태그
          if (!name) {
            const titleMatch = dHtml.match(/<title>([^<]+)<\/title>/);
            if (titleMatch) {
              name = titleMatch[1].replace(/\s*[:·\-|].*/g, '').trim();
            }
          }

          // 방법5: 전화번호 백업 추출
          if (!tel) {
            for (const tp of [/"phone"\s*:\s*"([^"]+)"/, /"tel"\s*:\s*"([^"]+)"/, /"virtualPhone"\s*:\s*"([^"]+)"/, /"virtualTel"\s*:\s*"([^"]+)"/, /href="tel:([^"]+)"/]) {
              const tm = dHtml.match(tp); if (tm) { tel = tm[1]; break; }
            }
          }

          // 방법6: 주소 백업
          if (!address) {
            const addrMatch = dHtml.match(/"roadAddress"\s*:\s*"([^"]+)"/) || dHtml.match(/"address"\s*:\s*"([^"]{10,})"/);
            if (addrMatch) address = addrMatch[1];
          }

          // 방법7: 카테고리 백업
          if (!category) {
            const catMatch = dHtml.match(/"category"\s*:\s*\[([^\]]+)\]/);
            if (catMatch) {
              try { category = JSON.parse('[' + catMatch[1] + ']').join(' > '); } catch(e) {}
            }
            if (!category) {
              const catMatch2 = dHtml.match(/"category"\s*:\s*"([^"]+)"/);
              if (catMatch2) category = catMatch2[1];
            }
          }
          return { rank, name, tel, address, category, placeId: pid };
        } catch (e) {
          return { rank, name: '', tel: '', address: '', category: '', placeId: pid };
        }
      }));
      results.push(...batchResults);
      console.log(`진행: ${Math.min(i + BATCH, targetIds.length)}/${targetIds.length}`);
      if (i + BATCH < targetIds.length) await new Promise(r => setTimeout(r, 200));
    }

    // 포인트 차감
    const used = results.length;
    const newPts = user.points - used;
    db.prepare('UPDATE users SET points = ? WHERE id = ?').run(newPts, req.user.userId);
    db.prepare('INSERT INTO point_history (user_id, amount, type, description) VALUES (?, ?, ?, ?)').run(
      req.user.userId, -used, 'use', `플레이스: ${keyword} (${used}건)`
    );

    const ok = results.filter(r => r.name).length;
    console.log(`\n완료: ${results.length}건 (성공: ${ok}건)`);
    console.log(`========================================\n`);

    res.json({
      success: true,
      data: results,
      usedPoints: used,
      remainingPoints: newPts,
      message: placeIds.length < er ? `검색 결과가 ${placeIds.length}개뿐이어서 ${results.length}건만 추출` : null
    });

  } catch (error) {
    console.error('크롤링 에러:', error.message);
    res.status(500).json({ error: '데이터 추출 중 오류: ' + error.message });
  }
});

// ============ 포인트 내역 ============
app.get('/api/history/points', requireLogin, async (req, res) => {
  const rows = db.prepare('SELECT * FROM point_history WHERE user_id = ? ORDER BY created_at DESC LIMIT 50').all(req.user.userId);
  res.json(rows);
});

// ============ 관리자 API ============
app.get('/api/admin/users', requireLogin, (req, res) => {
  if (!req.user.isAdmin) return res.status(403).json({ error: '관리자 권한이 필요합니다.' });
  const users = db.prepare('SELECT id, username, points, is_admin, created_at FROM users ORDER BY created_at DESC').all();
  res.json(users);
});

app.post('/api/admin/points', requireLogin, (req, res) => {
  if (!req.user.isAdmin) return res.status(403).json({ error: '관리자 권한이 필요합니다.' });
  const { userId, amount } = req.body;
  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(userId);
  if (!user) return res.status(404).json({ error: '사용자를 찾을 수 없습니다.' });
  const newPoints = user.points + amount;
  if (newPoints < 0) return res.status(400).json({ error: '포인트가 부족합니다.' });
  db.prepare('UPDATE users SET points = ? WHERE id = ?').run(newPoints, userId);
  db.prepare('INSERT INTO point_history (user_id, amount, type, description) VALUES (?, ?, ?, ?)').run(
    userId, amount, amount > 0 ? 'charge' : 'deduct', amount > 0 ? '관리자 지급' : '관리자 차감'
  );
  res.json({ success: true, newPoints });
});

// ============ 서버 시작 ============
app.listen(PORT, () => {
  console.log(`서버 실행 중: http://localhost:${PORT}`);
});
