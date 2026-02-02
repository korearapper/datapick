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
    
    // 네이버 지도 내부 API 직접 호출
    const allPlaceIds = [];
    const allPlaceData = []; // ID와 함께 기본 정보도 저장
    
    // 네이버 지도 검색 API (실제 사용되는 엔드포인트)
    for (let page = 1; page <= 10 && allPlaceIds.length < endRank + 20; page++) {
      const proxy = getNextProxy();
      const proxyUrl = `http://${proxy.auth.username}:${proxy.auth.password}@${proxy.host}:${proxy.port}`;
      const agent = new HttpsProxyAgent(proxyUrl);
      
      // 네이버 지도 실제 검색 API
      const searchUrl = `https://pcmap-api.place.naver.com/place/graphql`;
      
      const graphqlQuery = {
        operationName: "getPlacesList",
        variables: {
          input: {
            query: keyword,
            start: (page - 1) * 50 + 1,
            display: 50,
            adult: false,
            spq: false,
            queryRank: ""
          },
          isNmap: true
        },
        query: `query getPlacesList($input: PlacesInput, $isNmap: Boolean!) {
          businesses: places(input: $input) {
            total
            items {
              id
              name
              tel
              roadAddress
              address
              category
            }
          }
        }`
      };
      
      console.log(`GraphQL 페이지 ${page} 요청...`);
      
      try {
        const response = await axios.post(searchUrl, graphqlQuery, {
          httpsAgent: agent,
          timeout: 15000,
          headers: {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Accept': 'application/json',
            'Content-Type': 'application/json',
            'Referer': 'https://map.naver.com/',
            'Origin': 'https://map.naver.com',
          }
        });
        
        const data = response.data;
        const items = data?.data?.businesses?.items || [];
        
        console.log(`페이지 ${page}: ${items.length}개 발견`);
        
        if (items.length === 0) break;
        
        for (const item of items) {
          if (item.id && !allPlaceIds.includes(String(item.id))) {
            allPlaceIds.push(String(item.id));
            allPlaceData.push({
              id: String(item.id),
              name: item.name || '',
              tel: item.tel || '',
              address: item.roadAddress || item.address || '',
              category: item.category || ''
            });
          }
        }
        
        console.log(`총 ${allPlaceIds.length}개`);
        
        if (items.length < 50) break;
        
      } catch (e) {
        console.log(`GraphQL 페이지 ${page} 실패: ${e.message}`);
        
        // GraphQL 실패시 HTML 파싱으로 폴백
        if (page === 1) {
          console.log('HTML 파싱으로 전환...');
          
          const htmlUrl = `https://m.map.naver.com/search2/search.naver?query=${encodeURIComponent(keyword)}&sm=hty&style=v5`;
          
          try {
            const htmlResponse = await axios.get(htmlUrl, {
              httpsAgent: agent,
              timeout: 15000,
              headers: {
                'User-Agent': 'Mozilla/5.0 (iPhone; CPU iPhone OS 16_0 like Mac OS X) AppleWebKit/605.1.15',
              }
            });
            
            const html = htmlResponse.data;
            const patterns = [/place\/(\d{8,})/gi, /"id"\s*:\s*"?(\d{8,})"?/gi, /sid[=:][\s"']*(\d{8,})/gi];
            
            for (const pattern of patterns) {
              let match;
              pattern.lastIndex = 0;
              while ((match = pattern.exec(html)) !== null) {
                if (!allPlaceIds.includes(match[1])) {
                  allPlaceIds.push(match[1]);
                }
              }
            }
            
            console.log(`HTML에서 ${allPlaceIds.length}개 추출`);
          } catch (htmlErr) {
            console.log(`HTML도 실패: ${htmlErr.message}`);
          }
        }
        break;
      }
      
      await new Promise(r => setTimeout(r, 300));
    }
    
    console.log(`총 Place ID: ${allPlaceIds.length}개`);
    
    if (allPlaceIds.length === 0) {
      return res.status(400).json({ error: '검색 결과를 가져올 수 없습니다.' });
    }
    
    if (allPlaceIds.length < startRank) {
      return res.status(400).json({ error: `검색 결과가 ${allPlaceIds.length}개뿐입니다. 시작 순위(${startRank})보다 적습니다.` });
    }
    
    // GraphQL에서 이미 데이터를 가져왔으면 바로 사용
    const useGraphQLData = allPlaceData.length > 0;
    
    // 2단계: 상세 정보 가져오기
    const targetIds = allPlaceIds.slice(startRank - 1, endRank);
    const results = [];
    
    if (useGraphQLData) {
      // GraphQL에서 이미 데이터를 가져왔으면 바로 사용
      console.log('GraphQL 데이터 사용');
      const targetData = allPlaceData.slice(startRank - 1, endRank);
      
      for (let i = 0; i < targetData.length; i++) {
        const data = targetData[i];
        results.push({
          rank: startRank + i,
          name: data.name,
          tel: data.tel,
          address: data.address,
          category: data.category,
          placeId: data.id
        });
      }
      
      console.log(`GraphQL에서 ${results.length}건 완료`);
      
    } else {
      // HTML에서 ID만 가져왔으면 상세 페이지에서 정보 추출
      console.log('상세 페이지에서 정보 추출 시작...');
      const BATCH_SIZE = 5;
    
    for (let i = 0; i < targetIds.length; i += BATCH_SIZE) {
      const batch = targetIds.slice(i, i + BATCH_SIZE);
      
      const batchPromises = batch.map(async (placeId, idx) => {
        const rank = startRank + i + idx;
        
        try {
          const detailProxy = getNextProxy();
          const detailProxyUrl = `http://${detailProxy.auth.username}:${detailProxy.auth.password}@${detailProxy.host}:${detailProxy.port}`;
          const detailAgent = new HttpsProxyAgent(detailProxyUrl);
          
          const detailUrl = `https://m.place.naver.com/place/${placeId}/home`;
          
          const detailResponse = await axios.get(detailUrl, {
            httpsAgent: detailAgent,
            timeout: 10000,
            headers: {
              'User-Agent': 'Mozilla/5.0 (iPhone; CPU iPhone OS 16_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.0 Mobile/15E148 Safari/604.1',
              'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            }
          });
          
          const html = detailResponse.data;
          let name = '', tel = '', address = '', category = '';
          
          // Apollo State 파싱
          const apolloMatch = html.match(/window\.__APOLLO_STATE__\s*=\s*({.+?});?\s*<\/script>/s);
          if (apolloMatch) {
            try {
              const apolloData = JSON.parse(apolloMatch[1]);
              
              // PlaceDetailBase 찾기
              for (const key of Object.keys(apolloData)) {
                if (key.startsWith('PlaceDetailBase:')) {
                  const place = apolloData[key];
                  name = place.name || '';
                  address = place.roadAddress || place.address || '';
                  category = Array.isArray(place.category) ? place.category.join(' > ') : (place.category || '');
                  break;
                }
              }
              
              // 전화번호 찾기 (여러 키에서)
              for (const key of Object.keys(apolloData)) {
                const obj = apolloData[key];
                if (obj && typeof obj === 'object') {
                  if (obj.phone && !tel) tel = obj.phone;
                  if (obj.virtualPhone && !tel) tel = obj.virtualPhone;
                  if (obj.tel && !tel) tel = obj.tel;
                  if (obj.phoneNumber && !tel) tel = obj.phoneNumber;
                }
              }
            } catch (e) {}
          }
          
          // 전화번호 백업 추출 (HTML에서 직접)
          if (!tel) {
            const telPatterns = [
              /"phone"\s*:\s*"([^"]+)"/,
              /"virtualPhone"\s*:\s*"([^"]+)"/,
              /"tel"\s*:\s*"([^"]+)"/,
              /전화<\/span><[^>]*>([0-9\-]+)/,
              /href="tel:([^"]+)"/,
              /(\d{2,4}-\d{3,4}-\d{4})/
            ];
            for (const pattern of telPatterns) {
              const match = html.match(pattern);
              if (match && match[1]) {
                tel = match[1];
                break;
              }
            }
          }
          
          // 이름 백업 추출
          if (!name) {
            const nameMatch = html.match(/<meta[^>]*property="og:title"[^>]*content="([^"]*)"/) ||
                             html.match(/<title>([^<]+)</);
            if (nameMatch) {
              name = nameMatch[1].split(':')[0].split('-')[0].split('|')[0].trim();
            }
          }
          
          return { rank, name, tel, address, category, placeId };
          
        } catch (e) {
          return { rank, name: '', tel: '', address: '', category: '', placeId };
        }
      });
      
      const batchResults = await Promise.all(batchPromises);
      results.push(...batchResults);
      
      // 진행 상황 로그
      console.log(`진행: ${Math.min(i + BATCH_SIZE, targetIds.length)}/${targetIds.length}`);
      
      // 배치 간 딜레이
      if (i + BATCH_SIZE < targetIds.length) {
        await new Promise(r => setTimeout(r, 100));
      }
    }
    } // end of else (HTML 파싱 분기)
    
    // 순위순 정렬
    results.sort((a, b) => a.rank - b.rank);
    
    // 성공한 것만 카운트
    const successResults = results.filter(r => r.name);
    console.log(`크롤링 완료: ${results.length}건 (정보있음: ${successResults.length}건)`);
    
    const usedPoints = results.length;
    const newPoints = user.points - usedPoints;
    
    db.prepare('UPDATE users SET points = ? WHERE id = ?').run(newPoints, req.user.userId);
    db.prepare('INSERT INTO point_history (user_id, amount, type, description) VALUES (?, ?, ?, ?)').run(
      req.user.userId, -usedPoints, 'use', `플레이스 추출: ${keyword} (${results.length}건)`
    );
    
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
