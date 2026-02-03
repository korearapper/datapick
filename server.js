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

// ============ 프록시 (10,000개 포트 = 10,000개 IP) ============
const PROXY_HOST = 'kr.decodo.com';
const PROXY_USER = 'spuqtp2czv';
const PROXY_PASS = '1voaShrNj_2f4V3hgB';

const usedPorts = new Set();
function getProxyAgent() {
  let port;
  if (usedPorts.size > 9000) usedPorts.clear();
  do { port = 10001 + Math.floor(Math.random() * 10000); } while (usedPorts.has(port));
  usedPorts.add(port);
  return new HttpsProxyAgent(`http://${PROXY_USER}:${PROXY_PASS}@${PROXY_HOST}:${port}`);
}

const UAs = [
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36',
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36',
  'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36',
  'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.1 Safari/605.1.15',
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:133.0) Gecko/20100101 Firefox/133.0',
  'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36',
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36',
  'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36',
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:132.0) Gecko/20100101 Firefox/132.0',
  'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:133.0) Gecko/20100101 Firefox/133.0',
];
function randomUA() { return UAs[Math.floor(Math.random() * UAs.length)]; }
function sleep(ms) { return new Promise(r => setTimeout(r, ms)); }

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


// =====================================================
//  플레이스 크롤링 (최대 300건) - 프록시 IP 무제한 회전
// =====================================================
app.post('/api/extract/place', requireLogin, async (req, res) => {
  const { keyword, startRank, endRank } = req.body;
  if (!keyword) return res.status(400).json({ error: '키워드를 입력해주세요.' });
  const sr = parseInt(startRank) || 1;
  const er = parseInt(endRank) || 300;
  const count = er - sr + 1;
  const user = db.prepare('SELECT points FROM users WHERE id = ?').get(req.user.userId);
  if (user.points < count) return res.status(400).json({ error: `포인트 부족 (보유: ${user.points}P, 필요: ${count}P)` });

  try {
    console.log(`\n========== 플레이스: ${keyword} (${sr}~${er}위) ==========`);

    const allPlaceIds = [];
    const pagesNeeded = Math.ceil(er / 75);

    for (let page = 1; page <= Math.min(pagesNeeded, 5); page++) {
      for (let attempt = 0; attempt < 3; attempt++) {
        try {
          const agent = getProxyAgent();
          const searchUrl = `https://m.map.naver.com/search2/search.naver?query=${encodeURIComponent(keyword)}&sm=hty&style=v5${page > 1 ? '&page=' + page : ''}`;
          const searchRes = await axios.get(searchUrl, {
            httpsAgent: agent, timeout: 20000,
            headers: { 'User-Agent': 'Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15', 'Accept': 'text/html', 'Accept-Language': 'ko-KR,ko;q=0.9' }
          });
          const html = searchRes.data;
          const pageIds = [];
          for (const p of [/place\/([\d]{8,})/gi, /sid[=:][\s"']*([\d]{8,})/gi, /"id"\s*:\s*"?([\d]{8,})"?/gi]) {
            let m; while ((m = p.exec(html)) !== null) {
              if (!pageIds.includes(m[1]) && !allPlaceIds.includes(m[1])) pageIds.push(m[1]);
            }
          }
          allPlaceIds.push(...pageIds);
          console.log(`  페이지 ${page}: ${pageIds.length}개 ID (누적: ${allPlaceIds.length}개)`);
          if (pageIds.length < 10) break;
          break;
        } catch (e) {
          console.log(`  페이지 ${page} 시도${attempt + 1}: ${e.response?.status || e.message}`);
          if (attempt < 2) await sleep(1500 + attempt * 1000);
        }
      }
      if (allPlaceIds.length >= er) break;
      await sleep(600 + Math.random() * 400);
    }

    if (!allPlaceIds.length) return res.status(400).json({ error: '검색 결과 없음' });
    console.log(`  총 Place ID: ${allPlaceIds.length}개`);

    const targetIds = allPlaceIds.slice(sr - 1, Math.min(er, allPlaceIds.length));
    const results = [];
    const SKIP = ['네이버', 'naver', 'NAVER', '검색', '지도', '플레이스', 'place', 'map'];

    async function fetchPlace(pid, rank, retry = 0) {
      try {
        const agent = getProxyAgent();
        const ua = randomUA();
        const d = (await axios.get(`https://pcmap.place.naver.com/place/${pid}/home`, {
          httpsAgent: agent, timeout: 15000,
          headers: { 'User-Agent': ua, 'Accept': 'text/html,application/xhtml+xml', 'Accept-Language': 'ko-KR,ko;q=0.9', 'Referer': 'https://map.naver.com/' }
        })).data;

        let name = '', tel = '', address = '', category = '';
        for (const nm of d.matchAll(/"name"\s*:\s*"([^"]{2,60})"/g)) {
          const n = nm[1];
          if (SKIP.some(s => n.toLowerCase().includes(s.toLowerCase())) || n.startsWith('http') || n.startsWith('/')) continue;
          name = n; break;
        }
        const tm = d.match(/"(?:phone|tel|virtualPhone|virtualTel)"\s*:\s*"([0-9\-]+)"/) || d.match(/href="tel:([^"]+)"/);
        if (tm) tel = tm[1];
        const am = d.match(/"roadAddress"\s*:\s*"([^"]+)"/) || d.match(/"address"\s*:\s*"([^"]{10,})"/);
        if (am) address = am[1];
        const ca = d.match(/"category"\s*:\s*\[([^\]]+)\]/);
        if (ca) { try { category = JSON.parse('[' + ca[1] + ']').join(' > '); } catch(e) {} }
        if (!category) { const cm = d.match(/"category"\s*:\s*"([^"]+)"/); if (cm) category = cm[1]; }
        if (!name) {
          const og = d.match(/<meta\s+property="og:title"\s+content="([^"]+)"/);
          if (og) { const t = og[1].replace(/\s*[:·\-|].*/g, '').trim(); if (!SKIP.some(s => t.includes(s))) name = t; }
        }
        if (!name && retry < 4) { await sleep(1000 + retry * 800); return fetchPlace(pid, rank, retry + 1); }
        return { rank, name, tel, address, category, placeId: pid };
      } catch (e) {
        if (retry < 5) {
          if (retry === 0) console.log(`  ${rank}위 ${e.response?.status || '에러'} → 재시도`);
          await sleep(1500 + retry * 1200);
          return fetchPlace(pid, rank, retry + 1);
        }
        return { rank, name: '', tel: '', address: '', category: '', placeId: pid };
      }
    }

    let batchSize = 3;
    for (let i = 0; i < targetIds.length; i += batchSize) {
      const batch = targetIds.slice(i, i + batchSize);
      const br = await Promise.all(batch.map((pid, idx) => fetchPlace(pid, sr + i + idx)));
      results.push(...br);
      const fails = br.filter(r => !r.name).length;
      if (fails > 0 && batchSize > 1) { batchSize = Math.max(1, batchSize - 1); console.log(`  ⚠️ 배치 → ${batchSize}개`); }
      const done = Math.min(i + batchSize, targetIds.length);
      if (done % 15 === 0 || done === targetIds.length) console.log(`  진행: ${done}/${targetIds.length} (성공: ${results.filter(r => r.name).length})`);
      if (i + batchSize < targetIds.length) await sleep(batchSize === 1 ? 1500 + Math.random() * 1500 : 400 + Math.random() * 600);
    }

    const successResults = results.filter(r => r.name);
    const used = successResults.length;
    const newPts = user.points - used;
    db.prepare('UPDATE users SET points = ? WHERE id = ?').run(newPts, req.user.userId);
    db.prepare('INSERT INTO point_history (user_id, amount, type, description) VALUES (?, ?, ?, ?)').run(
      req.user.userId, -used, 'use', `플레이스: ${keyword} (성공 ${used}/${results.length}건)`);
    console.log(`완료: ${results.length}건 중 성공 ${used}건, ${used}P 차감\n`);
    res.json({ success: true, data: results, usedPoints: used, remainingPoints: newPts });
  } catch (error) {
    console.error('플레이스 에러:', error.message);
    res.status(500).json({ error: '데이터 추출 오류: ' + error.message });
  }
});


// =====================================================
//  스마트스토어 크롤링 (최대 500위) - 프록시 IP 무제한 회전
//  경로: naver.com → 스토어(shopping.naver.com) → 키워드 검색 → 가격비교
//  3단계 폴백: 스토어검색 → 가격비교 API → 가격비교 HTML
// =====================================================
app.post('/api/extract/store', requireLogin, async (req, res) => {
  const { keyword, startRank, endRank } = req.body;
  if (!keyword) return res.status(400).json({ error: '키워드를 입력해주세요.' });
  const sr = parseInt(startRank) || 1;
  const er = parseInt(endRank) || 500;
  const count = er - sr + 1;
  const user = db.prepare('SELECT points FROM users WHERE id = ?').get(req.user.userId);
  if (user.points < count) return res.status(400).json({ error: `포인트 부족 (보유: ${user.points}P, 필요: ${count}P)` });

  try {
    console.log(`\n========== 스마트스토어: ${keyword} (${sr}~${er}위) ==========`);
    console.log(`  경로: naver.com → 스토어 → 키워드 검색 → 가격비교`);

    let allProducts = [];
    const existingRanks = new Set();
    const ITEMS_PER_PAGE = 80;
    const totalPages = Math.ceil(er / ITEMS_PER_PAGE);

    // ── 워밍업: 스토어 메인 접속 (쿠키 획득 시뮬레이션) ──
    let warmupCookies = '';
    try {
      const warmAgent = getProxyAgent();
      const warmUA = randomUA();
      const warmRes = await axios.get('https://shopping.naver.com/ns/home', {
        httpsAgent: warmAgent, timeout: 15000, maxRedirects: 5,
        headers: {
          'User-Agent': warmUA,
          'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
          'Accept-Language': 'ko-KR,ko;q=0.9,en;q=0.3',
          'Referer': 'https://www.naver.com/',
          'Connection': 'keep-alive',
          'Sec-Fetch-Dest': 'document',
          'Sec-Fetch-Mode': 'navigate',
          'Sec-Fetch-Site': 'same-site',
        }
      });
      const setCookies = warmRes.headers['set-cookie'];
      if (setCookies) {
        warmupCookies = setCookies.map(c => c.split(';')[0]).join('; ');
      }
      console.log(`  ✓ 스토어 메인 접속 (쿠키: ${warmupCookies ? '획득' : '없음'})`);
    } catch (e) {
      console.log(`  ⚠ 스토어 워밍업 스킵: ${e.message}`);
    }
    await sleep(500 + Math.random() * 500);

    for (let page = 1; page <= totalPages; page++) {
      const offset = (page - 1) * ITEMS_PER_PAGE + 1;
      if (offset > er) break;

      let products = [];
      let success = false;

      // ══════════════════════════════════════════════════
      // 1차: 스토어 검색 API (shopping.naver.com 내부 API)
      //   경로: 스토어에서 키워드 검색 → 검색 결과 내부 API
      //   Referer: shopping.naver.com (자연스러운 경로)
      // ══════════════════════════════════════════════════
      for (let attempt = 0; attempt < 3 && !success; attempt++) {
        try {
          const agent = getProxyAgent();
          const ua = randomUA();
          // 스토어 검색 API - shopping.naver.com 내부 경로
          const storeApiUrl = `https://shopping.naver.com/ns/api/search?query=${encodeURIComponent(keyword)}&sort=POPULAR&pagingIndex=${page}&pagingSize=${ITEMS_PER_PAGE}&viewType=LIST`;
          const sRes = await axios.get(storeApiUrl, {
            httpsAgent: agent, timeout: 20000,
            headers: {
              'User-Agent': ua,
              'Accept': 'application/json, text/plain, */*',
              'Accept-Language': 'ko-KR,ko;q=0.9,en-US;q=0.8,en;q=0.7',
              'Accept-Encoding': 'gzip, deflate, br',
              'Referer': `https://shopping.naver.com/ns/home?query=${encodeURIComponent(keyword)}`,
              'Origin': 'https://shopping.naver.com',
              'Sec-Fetch-Dest': 'empty',
              'Sec-Fetch-Mode': 'cors',
              'Sec-Fetch-Site': 'same-origin',
              'Connection': 'keep-alive',
              ...(warmupCookies ? { 'Cookie': warmupCookies } : {}),
            }
          });
          const rData = sRes.data;
          // 스토어 API 응답 구조 탐색
          const extractProducts = (obj) => {
            if (!obj) return null;
            // 직접 products 배열
            if (obj.products && Array.isArray(obj.products)) return obj.products;
            if (obj.shoppingResult?.products) return obj.shoppingResult.products;
            if (obj.result?.products) return obj.result.products;
            if (obj.data?.products) return obj.data.products;
            // 깊이 탐색
            if (typeof obj === 'object') {
              for (const k of Object.keys(obj)) {
                if (Array.isArray(obj[k]) && obj[k].length > 3 && (obj[k][0]?.productTitle || obj[k][0]?.name || obj[k][0]?.title)) {
                  return obj[k];
                }
              }
              for (const k of Object.keys(obj)) {
                if (typeof obj[k] === 'object' && obj[k] !== null) {
                  const found = extractProducts(obj[k]);
                  if (found) return found;
                }
              }
            }
            return null;
          };
          const foundProducts = extractProducts(rData);
          if (foundProducts && foundProducts.length > 0) {
            products = foundProducts.map(item => ({
              productName: item.productTitle || item.name || item.title || '',
              storeName: item.mallName || item.shopName || item.storeName || '',
              price: item.price || item.lowPrice || item.salePrice || '',
              reviewCount: item.reviewCount || item.totalReviewCount || 0,
              category: item.category1Name || item.categoryName || '',
              productUrl: item.mallProductUrl || item.productUrl || item.crUrl || '',
              productId: item.id || item.nvMid || item.productId || '',
              image: item.imageUrl || item.thumbnailUrl || '',
              maker: item.maker || '', brand: item.brand || '',
            }));
            success = true;
            console.log(`  [스토어API] 페이지 ${page}: ${products.length}건 ✓`);
          }
        } catch (e) {
          console.log(`  [스토어API] 페이지 ${page} 시도${attempt + 1}: ${e.response?.status || e.message}`);
          await sleep(1500 + attempt * 1500);
        }
      }

      // ══════════════════════════════════════════════════
      // 2차: 가격비교 검색 (search.shopping.naver.com)
      //   경로: 스토어 검색 결과에서 "가격비교 검색에서 더보기" 클릭
      //   Referer: shopping.naver.com → search.shopping.naver.com
      //   핵심: 스토어에서 넘어온 것처럼 Referer & 헤더 세팅
      // ══════════════════════════════════════════════════
      if (!success) {
        for (let attempt = 0; attempt < 3 && !success; attempt++) {
          try {
            const agent = getProxyAgent();
            const ua = randomUA();
            // "가격비교 검색에서 더보기" 클릭 시뮬레이션
            const priceCompareUrl = `https://search.shopping.naver.com/search/all?query=${encodeURIComponent(keyword)}&pagingIndex=${page}&pagingSize=${ITEMS_PER_PAGE}&sort=rel&productSet=total&viewType=list`;
            const pcRes = await axios.get(priceCompareUrl, {
              httpsAgent: agent, timeout: 20000, maxRedirects: 5,
              headers: {
                'User-Agent': ua,
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
                'Accept-Language': 'ko-KR,ko;q=0.9,en-US;q=0.8,en;q=0.7',
                'Accept-Encoding': 'gzip, deflate, br',
                // 핵심: 스토어에서 넘어온 것처럼 Referer
                'Referer': `https://shopping.naver.com/ns/home?query=${encodeURIComponent(keyword)}`,
                'Sec-Fetch-Dest': 'document',
                'Sec-Fetch-Mode': 'navigate',
                'Sec-Fetch-Site': 'same-site',
                'Sec-Fetch-User': '?1',
                'Upgrade-Insecure-Requests': '1',
                'Connection': 'keep-alive',
                'Cache-Control': 'max-age=0',
                ...(warmupCookies ? { 'Cookie': warmupCookies } : {}),
              }
            });
            const html = pcRes.data;

            // __NEXT_DATA__ 파싱 시도
            const nextMatch = html.match(/<script id="__NEXT_DATA__"[^>]*>([\s\S]*?)<\/script>/);
            if (nextMatch) {
              try {
                const nd = JSON.parse(nextMatch[1]);
                const findProducts = (obj, depth = 0) => {
                  if (depth > 15 || !obj) return null;
                  if (Array.isArray(obj) && obj.length > 0 && (obj[0]?.item?.productTitle || obj[0]?.productTitle)) return obj;
                  if (typeof obj === 'object') {
                    for (const k of Object.keys(obj)) {
                      const f = findProducts(obj[k], depth + 1);
                      if (f) return f;
                    }
                  }
                  return null;
                };
                const found = findProducts(nd);
                if (found?.length > 0) {
                  products = found.map(p => {
                    const it = p.item || p;
                    return {
                      productName: it.productTitle || it.productName || '',
                      storeName: it.mallName || it.shopName || '',
                      price: it.price || it.lowPrice || '',
                      reviewCount: it.reviewCount || 0,
                      category: it.category1Name || '',
                      productUrl: it.mallProductUrl || '',
                      productId: it.id || it.nvMid || '',
                      image: it.imageUrl || '', maker: it.maker || '', brand: it.brand || '',
                    };
                  });
                  success = true;
                  console.log(`  [가격비교NEXT] 페이지 ${page}: ${products.length}건 ✓`);
                }
              } catch (pe) {
                console.log(`  [가격비교NEXT] 파싱 에러: ${pe.message}`);
              }
            }

            // __NEXT_DATA__ 실패 시 정규식 폴백
            if (!success) {
              const titles = [...html.matchAll(/"productTitle"\s*:\s*"([^"]{2,200})"/g)];
              const malls = [...html.matchAll(/"mallName"\s*:\s*"([^"]{1,100})"/g)];
              const prices = [...html.matchAll(/"price"\s*:\s*"?(\d+)"?/g)];
              if (titles.length > 0) {
                for (let j = 0; j < titles.length; j++) {
                  products.push({
                    productName: titles[j]?.[1] || '', storeName: malls[j]?.[1] || '',
                    price: prices[j]?.[1] || '', reviewCount: 0, category: '',
                    productUrl: '', productId: '', image: '', maker: '', brand: '',
                  });
                }
                success = true;
                console.log(`  [가격비교정규식] 페이지 ${page}: ${products.length}건 ✓`);
              }
            }
          } catch (e) {
            console.log(`  [가격비교] 페이지 ${page} 시도${attempt + 1}: ${e.response?.status || e.message}`);
            await sleep(2000 + attempt * 2000);
          }
        }
      }

      // ══════════════════════════════════════════════════
      // 3차: 가격비교 JSON API (search.shopping.naver.com/api)
      //   가격비교 페이지 내부에서 사용하는 API
      //   Referer: search.shopping.naver.com (가격비교 페이지에서 호출)
      // ══════════════════════════════════════════════════
      if (!success) {
        for (let attempt = 0; attempt < 3 && !success; attempt++) {
          try {
            const agent = getProxyAgent();
            const ua = randomUA();
            const apiUrl = `https://search.shopping.naver.com/api/search/all?query=${encodeURIComponent(keyword)}&sort=rel&pagingIndex=${page}&pagingSize=${ITEMS_PER_PAGE}&viewType=list&productSet=total`;
            const aRes = await axios.get(apiUrl, {
              httpsAgent: agent, timeout: 20000,
              headers: {
                'User-Agent': ua,
                'Accept': 'application/json, text/plain, */*',
                'Accept-Language': 'ko-KR,ko;q=0.9',
                'Accept-Encoding': 'gzip, deflate, br',
                // 가격비교 페이지 내부에서 호출하는 것처럼
                'Referer': `https://search.shopping.naver.com/search/all?query=${encodeURIComponent(keyword)}&pagingIndex=${page}`,
                'Origin': 'https://search.shopping.naver.com',
                'Sec-Fetch-Dest': 'empty',
                'Sec-Fetch-Mode': 'cors',
                'Sec-Fetch-Site': 'same-origin',
                ...(warmupCookies ? { 'Cookie': warmupCookies } : {}),
              }
            });
            if (aRes.data?.shoppingResult?.products) {
              products = aRes.data.shoppingResult.products.map(item => ({
                productName: item.productTitle || item.productName || '',
                storeName: item.mallName || item.shopName || '',
                price: item.price || item.lowPrice || '',
                reviewCount: item.reviewCount || item.totalReviewCount || 0,
                category: item.category1Name || '',
                productUrl: item.mallProductUrl || item.crUrl || '',
                productId: item.id || item.nvMid || '',
                image: item.imageUrl || '', maker: item.maker || '', brand: item.brand || '',
              }));
              success = true;
              console.log(`  [가격비교API] 페이지 ${page}: ${products.length}건 ✓`);
            }
          } catch (e) {
            console.log(`  [가격비교API] 페이지 ${page} 시도${attempt + 1}: ${e.response?.status || e.message}`);
            await sleep(2500 + attempt * 2000);
          }
        }
      }

      // ══════════════════════════════════════════════════
      // 4차: 모바일 가격비교 (최종 폴백)
      //   모바일 버전은 봇 감지가 약함
      // ══════════════════════════════════════════════════
      if (!success) {
        try {
          const agent = getProxyAgent();
          const mUrl = `https://msearch.shopping.naver.com/search/all?query=${encodeURIComponent(keyword)}&pagingIndex=${page}&sort=rel`;
          const mRes = await axios.get(mUrl, {
            httpsAgent: agent, timeout: 20000,
            headers: {
              'User-Agent': 'Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1',
              'Accept': 'text/html,application/xhtml+xml',
              'Accept-Language': 'ko-KR,ko;q=0.9',
              'Referer': 'https://m.shopping.naver.com/',
              'Sec-Fetch-Dest': 'document',
              'Sec-Fetch-Mode': 'navigate',
            }
          });
          const mHtml = mRes.data;
          // __NEXT_DATA__ 시도
          const mNext = mHtml.match(/<script id="__NEXT_DATA__"[^>]*>([\s\S]*?)<\/script>/);
          if (mNext) {
            try {
              const mnd = JSON.parse(mNext[1]);
              const findP = (o, d = 0) => {
                if (d > 15 || !o) return null;
                if (Array.isArray(o) && o.length > 0 && (o[0]?.item?.productTitle || o[0]?.productTitle)) return o;
                if (typeof o === 'object') { for (const k of Object.keys(o)) { const f = findP(o[k], d + 1); if (f) return f; } }
                return null;
              };
              const mFound = findP(mnd);
              if (mFound?.length > 0) {
                products = mFound.map(p => { const it = p.item || p; return {
                  productName: it.productTitle || '', storeName: it.mallName || '',
                  price: it.price || it.lowPrice || '', reviewCount: it.reviewCount || 0,
                  category: it.category1Name || '', productUrl: '', productId: it.id || '',
                  image: '', maker: '', brand: '',
                }; });
                success = true;
                console.log(`  [모바일NEXT] 페이지 ${page}: ${products.length}건 ✓`);
              }
            } catch (me) {}
          }
          // 정규식 폴백
          if (!success) {
            const mTitles = [...mHtml.matchAll(/"productTitle"\s*:\s*"([^"]{2,200})"/g)];
            const mMalls = [...mHtml.matchAll(/"mallName"\s*:\s*"([^"]{1,100})"/g)];
            const mPrices = [...mHtml.matchAll(/"price"\s*:\s*"?(\d+)"?/g)];
            if (mTitles.length > 0) {
              for (let j = 0; j < mTitles.length; j++) {
                products.push({
                  productName: mTitles[j]?.[1] || '', storeName: mMalls[j]?.[1] || '',
                  price: mPrices[j]?.[1] || '', reviewCount: 0, category: '',
                  productUrl: '', productId: '', image: '', maker: '', brand: '',
                });
              }
              success = true;
              console.log(`  [모바일정규식] 페이지 ${page}: ${products.length}건 ✓`);
            }
          }
          if (!success) console.log(`  ✗ 페이지 ${page}: 전체 실패`);
        } catch (e) {
          console.log(`  ✗ 페이지 ${page}: 최종 실패 (${e.response?.status || e.message})`);
        }
      }

      // ── 순위 매핑 & 중복 방지 ──
      for (let j = 0; j < products.length; j++) {
        const globalRank = (page - 1) * ITEMS_PER_PAGE + j + 1;
        if (globalRank < sr || globalRank > er || existingRanks.has(globalRank)) continue;
        allProducts.push({ rank: globalRank, ...products[j] });
        existingRanks.add(globalRank);
      }
      if (allProducts.length >= count) break;
      // 페이지 간 딜레이 (자연스러운 패턴)
      await sleep(1000 + Math.random() * 1000);
    }

    allProducts.sort((a, b) => a.rank - b.rank);
    const successResults = allProducts.filter(r => r.productName);
    const used = successResults.length;
    const newPts = user.points - used;
    db.prepare('UPDATE users SET points = ? WHERE id = ?').run(newPts, req.user.userId);
    db.prepare('INSERT INTO point_history (user_id, amount, type, description) VALUES (?, ?, ?, ?)').run(
      req.user.userId, -used, 'use', `스마트스토어: ${keyword} (성공 ${used}건)`);
    console.log(`완료: 총 ${allProducts.length}건 중 성공 ${used}건\n`);
    res.json({ success: true, data: allProducts, usedPoints: used, remainingPoints: newPts });
  } catch (error) {
    console.error('스마트스토어 에러:', error.message);
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
