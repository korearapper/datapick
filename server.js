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
const JWT_SECRET = process.env.JWT_SECRET || 'datapick-secret-key-2024-very-long-string';

app.set('trust proxy', 1);

// Database 초기화
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
  
  CREATE TABLE IF NOT EXISTS extraction_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    keyword TEXT,
    platform TEXT,
    count INTEGER,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id)
  );
`);

// 관리자 계정 생성
const adminExists = db.prepare('SELECT * FROM users WHERE username = ?').get('admin');
if (!adminExists) {
  const hashedPassword = bcrypt.hashSync('admin1234', 10);
  db.prepare('INSERT INTO users (username, password, points, is_admin) VALUES (?, ?, ?, ?)').run('admin', hashedPassword, 1000000, 1);
  console.log('관리자 계정 생성됨 - ID: admin, PW: admin1234, 포인트: 1,000,000');
}

// 프록시 리스트
const proxies = [];
for (let i = 10001; i <= 19999; i++) {
  proxies.push({
    host: 'kr.decodo.com',
    port: i,
    auth: { username: 'spuqtp2czv', password: '1voaShrNj_2f4V3hgB' }
  });
}

let proxyIndex = 0;
function getNextProxy() {
  const proxy = proxies[proxyIndex];
  proxyIndex = (proxyIndex + 1) % proxies.length;
  return proxy;
}

// 미들웨어
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));

// JWT 토큰 생성
function generateToken(user) {
  return jwt.sign(
    { userId: user.id, username: user.username, isAdmin: user.is_admin === 1 },
    JWT_SECRET,
    { expiresIn: '7d' }
  );
}

// JWT 인증 미들웨어
function requireLogin(req, res, next) {
  const token = req.cookies.token || req.headers.authorization?.replace('Bearer ', '');
  
  if (!token) {
    return res.status(401).json({ error: '로그인이 필요합니다.' });
  }
  
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch (err) {
    res.clearCookie('token');
    return res.status(401).json({ error: '로그인이 만료되었습니다.' });
  }
}

function requireAdmin(req, res, next) {
  const token = req.cookies.token || req.headers.authorization?.replace('Bearer ', '');
  
  if (!token) {
    return res.status(401).json({ error: '로그인이 필요합니다.' });
  }
  
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    if (!decoded.isAdmin) {
      return res.status(403).json({ error: '관리자 권한이 필요합니다.' });
    }
    req.user = decoded;
    next();
  } catch (err) {
    return res.status(401).json({ error: '로그인이 만료되었습니다.' });
  }
}

// ============ 인증 API ============

app.post('/api/register', (req, res) => {
  const { username, password } = req.body;
  
  if (!username || !password) {
    return res.status(400).json({ error: '아이디와 비밀번호를 입력해주세요.' });
  }
  
  if (username.length < 4 || password.length < 4) {
    return res.status(400).json({ error: '아이디와 비밀번호는 4자 이상이어야 합니다.' });
  }
  
  const existing = db.prepare('SELECT * FROM users WHERE username = ?').get(username);
  if (existing) {
    return res.status(400).json({ error: '이미 존재하는 아이디입니다.' });
  }
  
  const hashedPassword = bcrypt.hashSync(password, 10);
  db.prepare('INSERT INTO users (username, password, points) VALUES (?, ?, ?)').run(username, hashedPassword, 0);
  
  res.json({ success: true });
});

app.post('/api/login', (req, res) => {
  const { username, password } = req.body;
  
  const user = db.prepare('SELECT * FROM users WHERE username = ?').get(username);
  if (!user || !bcrypt.compareSync(password, user.password)) {
    return res.status(400).json({ error: '아이디 또는 비밀번호가 일치하지 않습니다.' });
  }
  
  const token = generateToken(user);
  
  res.cookie('token', token, {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'lax',
    maxAge: 7 * 24 * 60 * 60 * 1000
  });
  
  res.json({ 
    success: true,
    token,
    user: {
      id: user.id,
      username: user.username,
      points: user.points,
      isAdmin: user.is_admin === 1
    }
  });
});

app.post('/api/logout', (req, res) => {
  res.clearCookie('token');
  res.json({ success: true });
});

app.get('/api/me', requireLogin, (req, res) => {
  const user = db.prepare('SELECT id, username, points, is_admin FROM users WHERE id = ?').get(req.user.userId);
  if (!user) {
    return res.status(404).json({ error: '사용자를 찾을 수 없습니다.' });
  }
  res.json({
    id: user.id,
    username: user.username,
    points: user.points,
    isAdmin: user.is_admin === 1
  });
});

// ============ 관리자 API ============

app.get('/api/admin/users', requireAdmin, (req, res) => {
  const users = db.prepare('SELECT id, username, points, is_admin, created_at FROM users ORDER BY created_at DESC').all();
  res.json(users);
});

app.post('/api/admin/points', requireAdmin, (req, res) => {
  const { userId, amount, description } = req.body;
  
  if (!userId || amount === undefined) {
    return res.status(400).json({ error: '필수 정보가 누락되었습니다.' });
  }
  
  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(userId);
  if (!user) {
    return res.status(404).json({ error: '사용자를 찾을 수 없습니다.' });
  }
  
  const newPoints = user.points + parseInt(amount);
  if (newPoints < 0) {
    return res.status(400).json({ error: '포인트가 부족합니다.' });
  }
  
  db.prepare('UPDATE users SET points = ? WHERE id = ?').run(newPoints, userId);
  db.prepare('INSERT INTO point_history (user_id, amount, type, description) VALUES (?, ?, ?, ?)').run(
    userId, amount, amount > 0 ? 'charge' : 'deduct', description || (amount > 0 ? '관리자 지급' : '관리자 차감')
  );
  
  res.json({ success: true, newPoints });
});

// ============ 히스토리 API ============

app.get('/api/history/points', requireLogin, (req, res) => {
  const history = db.prepare('SELECT * FROM point_history WHERE user_id = ? ORDER BY created_at DESC LIMIT 50').all(req.user.userId);
  res.json(history);
});

// ============ 크롤링 API ============

app.post('/api/extract/place', requireLogin, async (req, res) => {
  const { keyword, startRank, endRank } = req.body;
  
  if (!keyword || !startRank || !endRank) {
    return res.status(400).json({ error: '키워드와 순위 구간을 입력해주세요.' });
  }
  
  const count = endRank - startRank + 1;
  if (count <= 0) {
    return res.status(400).json({ error: '올바른 순위 구간을 입력해주세요.' });
  }
  
  const user = db.prepare('SELECT points FROM users WHERE id = ?').get(req.user.userId);
  if (user.points < count) {
    return res.status(400).json({ error: `포인트가 부족합니다. 필요: ${count}P, 보유: ${user.points}P` });
  }
  
  try {
    console.log(`크롤링 시작: ${keyword}, ${startRank}~${endRank}위`);
    
    // 1단계: 검색 결과에서 place ID 목록 추출 (RACAN 방식)
    const proxy = getNextProxy();
    const proxyUrl = `http://${proxy.auth.username}:${proxy.auth.password}@${proxy.host}:${proxy.port}`;
    const agent = new HttpsProxyAgent(proxyUrl);
    
    const searchUrl = `https://m.map.naver.com/search2/search.naver?query=${encodeURIComponent(keyword)}&sm=hty&style=v5`;
    console.log(`검색 URL: ${searchUrl}`);
    
    const searchResponse = await axios.get(searchUrl, {
      httpsAgent: agent,
      timeout: 30000,
      headers: {
        'User-Agent': 'Mozilla/5.0 (iPhone; CPU iPhone OS 16_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.0 Mobile/15E148 Safari/604.1',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        'Accept-Language': 'ko-KR,ko;q=0.9',
      }
    });
    
    const html = searchResponse.data;
    console.log(`HTML 길이: ${html.length}자`);
    
    // Place ID 추출 (RACAN 방식)
    const idPattern = /sid[=:][\s"']*(\d{8,})/gi;
    const idPattern2 = /place\/(\d{8,})/gi;
    const idPattern3 = /"id"\s*:\s*"?(\d{8,})"?/gi;
    
    const allIds = [];
    let match;
    
    while ((match = idPattern.exec(html)) !== null) allIds.push(match[1]);
    while ((match = idPattern2.exec(html)) !== null) allIds.push(match[1]);
    while ((match = idPattern3.exec(html)) !== null) allIds.push(match[1]);
    
    // 중복 제거하면서 순서 유지
    const placeIds = [...new Set(allIds)];
    console.log(`발견된 Place ID: ${placeIds.length}개`);
    console.log(`처음 10개: ${placeIds.slice(0, 10).join(', ')}`);
    
    // 2단계: 각 place ID의 상세 정보 가져오기
    const results = [];
    const targetIds = placeIds.slice(startRank - 1, endRank);
    
    for (let i = 0; i < targetIds.length; i++) {
      const placeId = targetIds[i];
      const rank = startRank + i;
      
      try {
        const detailProxy = getNextProxy();
        const detailProxyUrl = `http://${detailProxy.auth.username}:${detailProxy.auth.password}@${detailProxy.host}:${detailProxy.port}`;
        const detailAgent = new HttpsProxyAgent(detailProxyUrl);
        
        const detailUrl = `https://m.place.naver.com/place/${placeId}/home`;
        
        const detailResponse = await axios.get(detailUrl, {
          httpsAgent: detailAgent,
          timeout: 15000,
          headers: {
            'User-Agent': 'Mozilla/5.0 (iPhone; CPU iPhone OS 16_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.0 Mobile/15E148 Safari/604.1',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'ko-KR,ko;q=0.9',
          }
        });
        
        const detailHtml = detailResponse.data;
        
        // Apollo State에서 데이터 추출
        let name = '', tel = '', address = '', category = '';
        
        const apolloMatch = detailHtml.match(/window\.__APOLLO_STATE__\s*=\s*({.+?});?\s*<\/script>/s);
        if (apolloMatch) {
          try {
            const apolloData = JSON.parse(apolloMatch[1]);
            const placeKey = Object.keys(apolloData).find(k => k.startsWith('PlaceDetailBase:'));
            if (placeKey && apolloData[placeKey]) {
              const place = apolloData[placeKey];
              name = place.name || '';
              address = place.roadAddress || place.address || '';
              category = place.category || '';
              tel = place.phone || place.virtualPhone || '';
            }
          } catch (e) {
            console.log(`Apollo 파싱 실패 (${placeId})`);
          }
        }
        
        // Apollo 실패시 OG 태그에서 추출
        if (!name) {
          const ogTitleMatch = detailHtml.match(/<meta[^>]*property="og:title"[^>]*content="([^"]*)"/) ||
                               detailHtml.match(/<meta[^>]*content="([^"]*)"[^>]*property="og:title"/);
          if (ogTitleMatch) {
            name = ogTitleMatch[1].split(':')[0].split('-')[0].split('|')[0].trim();
          }
        }
        
        // 전화번호 추출 (여러 패턴)
        if (!tel) {
          const telMatch = detailHtml.match(/"phone"\s*:\s*"([^"]+)"/) ||
                          detailHtml.match(/"tel"\s*:\s*"([^"]+)"/) ||
                          detailHtml.match(/전화[^\d]*(\d{2,4}-\d{3,4}-\d{4})/);
          if (telMatch) tel = telMatch[1];
        }
        
        results.push({ rank, name, tel, address, category, placeId });
        console.log(`[${rank}] ${name || placeId} - ${tel || '번호없음'}`);
        
        // 요청 간격
        if (i < targetIds.length - 1) {
          await new Promise(resolve => setTimeout(resolve, 300));
        }
        
      } catch (detailError) {
        console.log(`상세 정보 실패 (${placeId}): ${detailError.message}`);
        results.push({ rank, name: '', tel: '', address: '', category: '', placeId });
      }
    }
    
    const usedPoints = results.length;
    const newPoints = user.points - usedPoints;
    
    db.prepare('UPDATE users SET points = ? WHERE id = ?').run(newPoints, req.user.userId);
    db.prepare('INSERT INTO point_history (user_id, amount, type, description) VALUES (?, ?, ?, ?)').run(
      req.user.userId, -usedPoints, 'use', `플레이스 추출: ${keyword} (${results.length}건)`
    );
    
    console.log(`크롤링 완료: ${results.length}건`);
    
    res.json({
      success: true,
      data: results,
      usedPoints,
      remainingPoints: newPoints
    });
    
  } catch (error) {
    console.error('크롤링 에러:', error.message);
    res.status(500).json({ error: '데이터 추출 중 오류가 발생했습니다: ' + error.message });
  }
});

app.listen(PORT, () => {
  console.log(`서버 실행 중: http://localhost:${PORT}`);
});
