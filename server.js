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
      
      const searchUrl = 'https://map.naver.com/p/search/' + encodeURIComponent(keyword);
      console.log('페이지 이동: ' + searchUrl);
      
      await page.goto(searchUrl, { waitUntil: 'networkidle2', timeout: 60000 });
      
      // 페이지 로딩 대기 (충분히)
      console.log('페이지 로딩 대기...');
      await new Promise(r => setTimeout(r, 5000));
      
      // searchIframe 찾기
      console.log('검색 프레임 찾는 중...');
      let frame = null;
      
      for (let i = 0; i < 15; i++) {
        const iframeHandle = await page.$('iframe#searchIframe');
        if (iframeHandle) {
          frame = await iframeHandle.contentFrame();
          if (frame) {
            // iframe 내부 컨텐츠 로딩 대기
            await new Promise(r => setTimeout(r, 3000));
            
            // place 링크가 있는지 확인
            const hasContent = await frame.evaluate(() => {
              return document.querySelectorAll('a[href*="place"]').length > 0 ||
                     document.querySelectorAll('li').length > 10;
            });
            
            if (hasContent) {
              console.log('iframe 컨텐츠 로딩 완료');
              break;
            }
          }
        }
        console.log('대기 중... ' + (i + 1) + '/15');
        await new Promise(r => setTimeout(r, 2000));
      }
      
      if (!frame) {
        frame = page;
        console.log('iframe 없음, 메인 페이지 사용');
      } else {
        console.log('검색 iframe 발견');
      }
      
      // 추가 대기 - 검색 결과 완전 로딩
      await new Promise(r => setTimeout(r, 3000));
      
      // 스크롤하면서 데이터 수집
      let prevCount = 0;
      let noChangeCount = 0;
      
      // 디버깅: iframe 내부 HTML 구조 확인
      const debugHtml = await frame.evaluate(() => {
        return {
          bodyHtml: document.body.innerHTML.substring(0, 3000),
          listItems: document.querySelectorAll('li').length,
          divItems: document.querySelectorAll('div').length,
          aLinks: document.querySelectorAll('a[href*="place"]').length,
          classes: [...new Set([...document.querySelectorAll('*')].map(el => el.className).filter(c => c))].slice(0, 50)
        };
      });
      
      console.log('iframe 내부 li 개수: ' + debugHtml.listItems);
      console.log('iframe 내부 div 개수: ' + debugHtml.divItems);
      console.log('place 링크 개수: ' + debugHtml.aLinks);
      console.log('발견된 클래스: ' + debugHtml.classes.join(', ').substring(0, 500));
      console.log('HTML 샘플: ' + debugHtml.bodyHtml.substring(0, 1000));
      
      while (allPlaceData.length < endRank && noChangeCount < 8) {
        const places = await frame.evaluate(() => {
          const results = [];
          
          // 모든 a 태그에서 place 링크 찾기
          const allLinks = document.querySelectorAll('a[href*="/place/"]');
          console.log('찾은 place 링크: ' + allLinks.length);
          
          const processedIds = new Set();
          
          allLinks.forEach(link => {
            const href = link.getAttribute('href') || '';
            const match = href.match(/place\/(\d+)/);
            
            if (match && !processedIds.has(match[1])) {
              const placeId = match[1];
              processedIds.add(placeId);
              
              // 부모 요소에서 정보 추출
              let name = '';
              let category = '';
              let address = '';
              
              // 링크 텍스트 또는 부모에서 이름 찾기
              const parent = link.closest('li') || link.closest('div') || link.parentElement;
              
              if (link.textContent.trim()) {
                name = link.textContent.trim().split('\n')[0];
              }
              
              if (parent) {
                // 이름이 없으면 부모에서 찾기
                if (!name) {
                  const nameEl = parent.querySelector('span, strong, b');
                  if (nameEl) name = nameEl.textContent.trim();
                }
                
                // 텍스트 노드에서 추출
                const allText = parent.textContent.split('\n').map(t => t.trim()).filter(t => t);
                if (allText.length > 0 && !name) name = allText[0];
                if (allText.length > 1) category = allText[1];
                if (allText.length > 2) address = allText.slice(2).join(' ');
              }
              
              if (placeId) {
                results.push({ 
                  placeId: placeId, 
                  name: name || ('업체 ' + placeId), 
                  category: category, 
                  address: address 
                });
              }
            }
          });
          
          return results;
        });
        
        for (const place of places) {
          const exists = allPlaceData.some(p => p.placeId === place.placeId);
          if (!exists && place.placeId) {
            allPlaceData.push(place);
          }
        }
        
        console.log('스크롤 중... ' + allPlaceData.length + '개');
        
        if (allPlaceData.length === prevCount) {
          noChangeCount++;
          await frame.evaluate(() => {
            // 모든 가능한 스크롤 컨테이너 시도
            document.querySelectorAll('div').forEach(div => {
              if (div.scrollHeight > div.clientHeight) {
                div.scrollTop = div.scrollHeight;
              }
            });
            window.scrollTo(0, document.body.scrollHeight);
          });
          await new Promise(r => setTimeout(r, 2000));
        } else {
          noChangeCount = 0;
        }
        prevCount = allPlaceData.length;
        
        await frame.evaluate(() => {
          const el = document.querySelector('#_pcmap_list_scroll_container') ||
                    document.querySelector('.Ryr1F') ||
                    document.body;
          if (el) {
            el.scrollTop = el.scrollHeight;
          }
        });
        
        await new Promise(r => setTimeout(r, 1500));
      }
      
      console.log('스크롤 완료: ' + allPlaceData.length + '개');
      
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
