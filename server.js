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

// 기본 관리자 계정
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

// 프록시 설정
const PROXY_HOST = 'gate.decodo.com';
const PROXY_USER = 'sph9s9jqsh';
const PROXY_PASS = 'KdRv7FXSJG6k7~a_country-kr';

let proxyIndex = 0;
function getNextProxy() {
  const port = 10001 + (proxyIndex % 100);
  proxyIndex++;
  return {
    host: PROXY_HOST,
    port: port,
    auth: { username: PROXY_USER, password: PROXY_PASS }
  };
}

// JWT 인증
function requireLogin(req, res, next) {
  const token = req.cookies.token || req.headers.authorization?.replace('Bearer ', '');
  if (!token) return res.status(401).json({ error: '로그인이 필요합니다.' });
  
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch (e) {
    return res.status(401).json({ error: '유효하지 않은 토큰입니다.' });
  }
}

// 로그인
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

// 내 정보
app.get('/api/me', requireLogin, (req, res) => {
  const user = db.prepare('SELECT id, username, points, is_admin FROM users WHERE id = ?').get(req.user.userId);
  res.json({ user });
});

// 로그아웃
app.post('/api/logout', (req, res) => {
  res.clearCookie('token');
  res.json({ success: true });
});

// ============ 크롤링 API ============

app.post('/api/extract/place', requireLogin, async (req, res) => {
  const { keyword, startRank, endRank } = req.body;
  
  if (!keyword || !startRank || !endRank) {
    return res.status(400).json({ error: '키워드와 순위 구간을 입력해주세요.' });
  }
  
  const count = endRank - startRank + 1;
  const user = db.prepare('SELECT points FROM users WHERE id = ?').get(req.user.userId);
  if (user.points < count) {
    return res.status(400).json({ error: '포인트가 부족합니다. 필요: ' + count + 'P, 보유: ' + user.points + 'P' });
  }
  
  try {
    console.log('크롤링 시작: ' + keyword + ', ' + startRank + '~' + endRank + '위');
    
    const allPlaceIds = [];
    
    // 1단계: 모바일 페이지에서 Place ID 수집
    const proxy = getNextProxy();
    const agent = new HttpsProxyAgent({
      host: proxy.host,
      port: proxy.port,
      auth: proxy.auth.username + ':' + proxy.auth.password
    });
    
    const mobileUrl = 'https://m.map.naver.com/search2/search.naver?query=' + encodeURIComponent(keyword) + '&sm=hty&style=v5';
    console.log('모바일 페이지 요청... (프록시: ' + proxy.host + ':' + proxy.port + ')');
    
    const response = await axios.get(mobileUrl, {
      httpsAgent: agent,
      timeout: 30000,
      headers: {
        'User-Agent': 'Mozilla/5.0 (iPhone; CPU iPhone OS 16_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.0 Mobile/15E148 Safari/604.1',
        'Accept': 'text/html,application/xhtml+xml',
        'Accept-Language': 'ko-KR,ko;q=0.9',
      }
    });
    
    const html = response.data;
    
    // Place ID 추출
    const patterns = [
      /place\/(\d{8,})/gi,
      /"id"\s*:\s*"?(\d{8,})"?/gi,
      /sid[=:][\s"']*(\d{8,})/gi,
    ];
    
    for (const pattern of patterns) {
      let match;
      while ((match = pattern.exec(html)) !== null) {
        if (!allPlaceIds.includes(match[1])) {
          allPlaceIds.push(match[1]);
        }
      }
    }
    
    console.log('Place ID 수집: ' + allPlaceIds.length + '개');
    
    // 최대 75개 제한 안내
    if (allPlaceIds.length < endRank) {
      console.log('참고: 네이버 지도 제한으로 최대 ' + allPlaceIds.length + '개까지만 수집 가능');
    }
    
    if (allPlaceIds.length === 0) {
      return res.status(400).json({ error: '검색 결과를 찾을 수 없습니다.' });
    }
    
    // 2단계: 상세 정보 수집 (병렬 처리)
    const targetIds = allPlaceIds.slice(startRank - 1, Math.min(endRank, allPlaceIds.length));
    const results = [];
    const BATCH_SIZE = 5;
    
    console.log('상세 정보 수집 시작: ' + targetIds.length + '건');
    
    for (let i = 0; i < targetIds.length; i += BATCH_SIZE) {
      const batch = targetIds.slice(i, i + BATCH_SIZE);
      
      const batchPromises = batch.map(async (placeId, idx) => {
        const rank = startRank + i + idx;
        
        try {
          const detailProxy = getNextProxy();
          const detailAgent = new HttpsProxyAgent({
            host: detailProxy.host,
            port: detailProxy.port,
            auth: detailProxy.auth.username + ':' + detailProxy.auth.password
          });
          
          const detailUrl = 'https://m.place.naver.com/place/' + placeId + '/home';
          
          const detailRes = await axios.get(detailUrl, {
            httpsAgent: detailAgent,
            timeout: 15000,
            headers: {
              'User-Agent': 'Mozilla/5.0 (iPhone; CPU iPhone OS 16_0 like Mac OS X) AppleWebKit/605.1.15',
            }
          });
          
          const detailHtml = detailRes.data;
          let name = '', tel = '', address = '', category = '';
          
          // Apollo State에서 추출
          const apolloMatch = detailHtml.match(/__APOLLO_STATE__\s*=\s*({.+?});?\s*<\/script>/s);
          if (apolloMatch) {
            try {
              const apolloData = JSON.parse(apolloMatch[1]);
              
              for (const key of Object.keys(apolloData)) {
                const obj = apolloData[key];
                if (obj && typeof obj === 'object') {
                  if (!name && obj.name) name = obj.name;
                  if (!address && (obj.roadAddress || obj.address)) address = obj.roadAddress || obj.address;
                  if (!category && obj.category) {
                    category = Array.isArray(obj.category) ? obj.category.join(' > ') : obj.category;
                  }
                  if (!tel && (obj.phone || obj.tel || obj.virtualPhone)) {
                    tel = obj.phone || obj.tel || obj.virtualPhone;
                  }
                }
              }
            } catch (e) {}
          }
          
          // HTML에서 백업 추출
          if (!tel) {
            const telMatch = detailHtml.match(/"phone"\s*:\s*"([^"]+)"/) ||
                            detailHtml.match(/"tel"\s*:\s*"([^"]+)"/) ||
                            detailHtml.match(/href="tel:([^"]+)"/);
            if (telMatch) tel = telMatch[1];
          }
          
          if (!name) {
            const nameMatch = detailHtml.match(/<meta[^>]*property="og:title"[^>]*content="([^"]+)"/);
            if (nameMatch) name = nameMatch[1].split(':')[0].trim();
          }
          
          return { rank, name, tel, address, category, placeId };
          
        } catch (e) {
          return { rank, name: '', tel: '', address: '', category: '', placeId };
        }
      });
      
      const batchResults = await Promise.all(batchPromises);
      results.push(...batchResults);
      
      console.log('진행: ' + Math.min(i + BATCH_SIZE, targetIds.length) + '/' + targetIds.length);
    }
    
    // 포인트 차감
    const usedPoints = results.length;
    const newPoints = user.points - usedPoints;
    
    db.prepare('UPDATE users SET points = ? WHERE id = ?').run(newPoints, req.user.userId);
    db.prepare('INSERT INTO point_history (user_id, amount, type, description) VALUES (?, ?, ?, ?)').run(
      req.user.userId, -usedPoints, 'use', '플레이스 추출: ' + keyword + ' (' + results.length + '건)'
    );
    
    const successCount = results.filter(r => r.name).length;
    console.log('크롤링 완료: ' + results.length + '건 (정보있음: ' + successCount + '건)');
    
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
  console.log('서버 실행 중: http://localhost:' + PORT);
});
