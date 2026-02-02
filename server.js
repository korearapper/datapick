const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const Database = require('better-sqlite3');
const axios = require('axios');
const { HttpsProxyAgent } = require('https-proxy-agent');
const path = require('path');
const puppeteer = require('puppeteer-extra');
const StealthPlugin = require('puppeteer-extra-plugin-stealth');

// Stealth 플러그인 적용 (봇 감지 우회)
puppeteer.use(StealthPlugin());

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
    return res.status(400).json({ error: '포인트가 부족합니다. 필요: ' + count + 'P, 보유: ' + user.points + 'P' });
  }
  
  try {
    console.log('크롤링 시작: ' + keyword + ', ' + startRank + '~' + endRank + '위');
    
    const allPlaceData = [];
    const capturedIds = new Set();
    
    // Puppeteer 브라우저 실행
    console.log('브라우저 시작...');
    const browser = await puppeteer.launch({
      headless: 'new',
      executablePath: process.env.PUPPETEER_EXECUTABLE_PATH || undefined,
      args: [
        '--no-sandbox',
        '--disable-setuid-sandbox',
        '--disable-dev-shm-usage',
        '--disable-accelerated-2d-canvas',
        '--disable-gpu',
        '--window-size=1920,1080',
      ]
    });
    
    try {
      const page = await browser.newPage();
      await page.setViewport({ width: 1920, height: 1080 });
      await page.setUserAgent('Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36');
      
      // 먼저 메인 페이지 방문 (쿠키/세션 설정)
      const searchUrl = 'https://map.naver.com/p/search/' + encodeURIComponent(keyword);
      console.log('페이지 이동: ' + searchUrl);
      
      await page.goto(searchUrl, { waitUntil: 'networkidle2', timeout: 60000 });
      await new Promise(r => setTimeout(r, 3000));
      
      // API 직접 호출로 페이지네이션
      console.log('API 직접 호출 시작...');
      
      // 페이지에서 현재 검색 좌표 추출 시도
      let searchCoord = '';
      try {
        searchCoord = await page.evaluate(() => {
          // URL에서 좌표 추출
          const url = window.location.href;
          const match = url.match(/c=([\d.]+),([\d.]+)/);
          if (match) return match[1] + ';' + match[2];
          
          // 또는 전역 변수에서
          if (window.__SEARCH_COORD__) return window.__SEARCH_COORD__;
          
          return '';
        });
      } catch (e) {}
      
      // 좌표가 없으면 인천 좌표 사용
      if (!searchCoord) {
        searchCoord = '126.7052062;37.4559418'; // 인천 좌표
      }
      
      console.log('검색 좌표: ' + searchCoord);
      
      for (let start = 1; start <= 500 && allPlaceData.length < endRank; start += 50) {
        // 여러 API URL 형식 시도
        const apiUrl = 'https://map.naver.com/p/api/search/allSearch' +
                      '?query=' + encodeURIComponent(keyword) +
                      '&type=all' +
                      '&searchCoord=' + encodeURIComponent(searchCoord) +
                      '&boundary=' +
                      '&start=' + start +
                      '&display=50' +
                      '&adult=false' +
                      '&spq=false' +
                      '&queryRank=' +
                      '&lang=ko';
        
        console.log('API 호출 (start=' + start + ')...');
        
        try {
          const response = await page.evaluate(async (url) => {
            try {
              const res = await fetch(url, {
                method: 'GET',
                credentials: 'include',
                headers: {
                  'Accept': 'application/json, text/plain, */*',
                  'Referer': window.location.href
                }
              });
              const text = await res.text();
              return { status: res.status, text: text };
            } catch (e) {
              return { error: e.message };
            }
          }, apiUrl);
          
          if (response.error) {
            console.log('Fetch 에러: ' + response.error);
            break;
          }
          
          if (response.status !== 200) {
            console.log('응답 상태: ' + response.status + ', ' + response.text.substring(0, 200));
            break;
          }
          
          const json = JSON.parse(response.text);
          
          // place 리스트 추출
          const placeList = json?.result?.place?.list || [];
          const totalCount = json?.result?.place?.totalCount || 0;
          
          console.log('결과: ' + placeList.length + '개 (전체: ' + totalCount + '개)');
          
          if (placeList.length === 0 && start === 1) {
            // 디버깅 - 응답 구조 확인
            console.log('응답 키: ' + JSON.stringify(Object.keys(json?.result || {})));
            console.log('응답 샘플: ' + response.text.substring(0, 500));
          }
          
          if (placeList.length === 0) {
            break;
          }
          
          for (const item of placeList) {
            const placeId = String(item.id || item.sid || '');
            if (placeId && !capturedIds.has(placeId)) {
              capturedIds.add(placeId);
              allPlaceData.push({
                placeId: placeId,
                name: item.name || item.title || '',
                tel: item.tel || item.phone || item.virtualPhone || '',
                category: Array.isArray(item.category) ? item.category.join(' > ') : (item.category || ''),
                address: item.roadAddress || item.address || ''
              });
            }
          }
          
          console.log('누적: ' + allPlaceData.length + '개');
          
          if (allPlaceData.length >= totalCount || placeList.length < 50) {
            console.log('모든 결과 수집 완료');
            break;
          }
          
          await new Promise(r => setTimeout(r, 300));
          
        } catch (e) {
          console.log('API 호출 실패: ' + e.message);
          break;
        }
      }
      
      // API 실패 시 네트워크 캡처 방식으로 폴백
      if (allPlaceData.length === 0) {
        console.log('API 직접 호출 실패, 네트워크 캡처로 재시도...');
        
        // 페이지 리로드하면서 응답 캡처
        await page.setRequestInterception(true);
        
        page.on('request', req => req.continue());
        
        page.on('response', async res => {
          const url = res.url();
          if (url.includes('allSearch') && url.includes('query')) {
            try {
              const json = await res.json();
              const list = json?.result?.place?.list || [];
              console.log('캡처: ' + list.length + '개');
              
              for (const item of list) {
                const placeId = String(item.id || '');
                if (placeId && !capturedIds.has(placeId)) {
                  capturedIds.add(placeId);
                  allPlaceData.push({
                    placeId,
                    name: item.name || '',
                    tel: item.tel || item.phone || '',
                    category: Array.isArray(item.category) ? item.category.join(' > ') : '',
                    address: item.roadAddress || item.address || ''
                  });
                }
              }
            } catch (e) {}
          }
        });
        
        await page.reload({ waitUntil: 'networkidle2' });
        await new Promise(r => setTimeout(r, 5000));
        
        console.log('캡처 완료: ' + allPlaceData.length + '개');
      }
      
      console.log('API 호출 완료: ' + allPlaceData.length + '개');
      
    } finally {
      await browser.close();
      console.log('브라우저 종료');
    }
    
    if (allPlaceData.length === 0) {
      return res.status(400).json({ error: '검색 결과를 가져올 수 없습니다.' });
    }
    
    const targetData = allPlaceData.slice(startRank - 1, Math.min(endRank, allPlaceData.length));
    const results = [];
    
    const BATCH_SIZE = 5;
    
    for (let i = 0; i < targetData.length; i += BATCH_SIZE) {
      const batch = targetData.slice(i, i + BATCH_SIZE);
      
      const batchPromises = batch.map(async (place, idx) => {
        const rank = startRank + i + idx;
        let tel = '';
        
        if (place.placeId) {
          try {
            const proxy = getNextProxy();
            const proxyUrl = 'http://' + proxy.auth.username + ':' + proxy.auth.password + '@' + proxy.host + ':' + proxy.port;
            const agent = new HttpsProxyAgent(proxyUrl);
            
            const response = await axios.get('https://m.place.naver.com/place/' + place.placeId + '/home', {
              httpsAgent: agent,
              timeout: 10000,
              headers: { 'User-Agent': 'Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X)' }
            });
            
            const html = response.data;
            
            // 여러 패턴으로 전화번호 추출
            const telPatterns = [
              /"phone"\s*:\s*"([^"]+)"/,
              /"tel"\s*:\s*"([^"]+)"/,
              /"virtualPhone"\s*:\s*"([^"]+)"/,
              /"virtualTel"\s*:\s*"([^"]+)"/,
              /href="tel:([^"]+)"/,
              /"phoneNumber"\s*:\s*"([^"]+)"/,
              /전화[^0-9]*([0-9]{2,4}-[0-9]{3,4}-[0-9]{4})/,
              /([0-9]{2,4}-[0-9]{3,4}-[0-9]{4})/
            ];
            
            for (const pattern of telPatterns) {
              const match = html.match(pattern);
              if (match && match[1] && match[1].includes('-')) {
                tel = match[1];
                break;
              }
            }
            
            // Apollo State에서도 추출 시도
            if (!tel) {
              const apolloMatch = html.match(/__APOLLO_STATE__\s*=\s*({.+?});?\s*<\/script>/s);
              if (apolloMatch) {
                try {
                  const apolloData = JSON.parse(apolloMatch[1]);
                  for (const key of Object.keys(apolloData)) {
                    const obj = apolloData[key];
                    if (obj && typeof obj === 'object') {
                      if (obj.phone) { tel = obj.phone; break; }
                      if (obj.virtualPhone) { tel = obj.virtualPhone; break; }
                      if (obj.tel) { tel = obj.tel; break; }
                    }
                  }
                } catch (e) {}
              }
            }
          } catch (e) {
            console.log('전화번호 조회 실패: ' + place.placeId);
          }
        }
        
        return { rank: rank, name: place.name, tel: tel, address: place.address, category: place.category, placeId: place.placeId };
      });
      
      const batchResults = await Promise.all(batchPromises);
      results.push(...batchResults);
      
      console.log('진행: ' + Math.min(i + BATCH_SIZE, targetData.length) + '/' + targetData.length);
    }
    
    const usedPoints = results.length;
    const newPoints = user.points - usedPoints;
    
    db.prepare('UPDATE users SET points = ? WHERE id = ?').run(newPoints, req.user.userId);
    db.prepare('INSERT INTO point_history (user_id, amount, type, description) VALUES (?, ?, ?, ?)').run(
      req.user.userId, -usedPoints, 'use', '플레이스 추출: ' + keyword + ' (' + results.length + '건)'
    );
    
    console.log('크롤링 완료: ' + results.length + '건');
    
    res.json({
      success: true,
      data: results,
      usedPoints: usedPoints,
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
