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
//  ※ search.shopping.naver.com = 418 차단 (데이터센터 IP 감지)
//  ※ 대안: search.naver.com 통합검색 쇼핑탭 (where=shp) 활용
//  3단계 폴백: 통합검색 쇼핑HTML → 모바일 통합검색 → 네이버 검색광고 API
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
    console.log(`  경로: search.naver.com 통합검색 쇼핑탭 (where=shp)`);

    let allProducts = [];
    const existingRanks = new Set();
    const ITEMS_PER_PAGE = 40;  // 네이버 통합검색 쇼핑탭은 페이지당 40개
    const totalPages = Math.ceil(er / ITEMS_PER_PAGE);

    // ── 워밍업: 네이버 메인 접속 (쿠키 획득) ──
    let warmupCookies = '';
    try {
      const warmAgent = getProxyAgent();
      const warmRes = await axios.get('https://www.naver.com/', {
        httpsAgent: warmAgent, timeout: 10000, maxRedirects: 3,
        headers: {
          'User-Agent': randomUA(),
          'Accept': 'text/html,application/xhtml+xml',
          'Accept-Language': 'ko-KR,ko;q=0.9',
        }
      });
      const setCookies = warmRes.headers['set-cookie'];
      if (setCookies) {
        warmupCookies = setCookies.map(c => c.split(';')[0]).join('; ');
      }
      console.log(`  ✓ 네이버 메인 접속 (쿠키: ${warmupCookies ? '획득' : '없음'})`);
    } catch (e) {
      console.log(`  ⚠ 워밍업 스킵: ${e.message}`);
    }
    await sleep(300 + Math.random() * 400);

    for (let page = 1; page <= totalPages; page++) {
      const startIdx = (page - 1) * ITEMS_PER_PAGE + 1;
      if (startIdx > er) break;

      let products = [];
      let success = false;

      // ── 공통 헬퍼 함수 (모든 단계에서 사용) ──
      const isAd = (item) => {
        if (!item || typeof item !== 'object') return false;
        if (item.adId || item.adcrUrl || item.isAd === true) return true;
        if (item.adType || item.adExtraInfo || item.adRank) return true;
        return false;
      };

      // HTML 마크업 제거 헬퍼 (\u003Cmark\u003E이어폰\u003C/mark\u003E → 이어폰)
      const cleanName = (s) => {
        if (!s) return '';
        return s
          .replace(/\\u003C[^>]*\\u003E/gi, '')  // \u003Cmark\u003E 형태
          .replace(/\\u003C\/[^>]*\\u003E/gi, '') 
          .replace(/<[^>]*>/g, '')               // <mark> 형태
          .replace(/\u003C[^>]*\u003E/g, '')     // 디코딩된 형태
          .trim();
      };

      const extractProduct = (it) => {
        if (!it || typeof it !== 'object') return null;
        const raw = it.item || it;
        // ★ productName 우선 (통합검색 쇼핑탭 실제 필드)
        const rawName = raw.productName || raw.productNameOrg || raw.standardProductName ||
                        raw.productTitle || raw.dispName || raw.name || raw.title || '';
        const name = cleanName(rawName);
        if (!name || name.length < 2) return null;
        if (/^(파워링크|광고|AD|sponsored|프로모션|브랜드검색)/i.test(name)) return null;
        return {
          productName: name,
          storeName: raw.mallName || raw.dispMallName || raw.shopName || raw.seller || '',
          price: raw.price || raw.lowPrice || raw.salePrice || raw.dispSalePrice || raw.dispDiscountedSalePrice || raw.dispPrice || '',
          reviewCount: raw.reviewCount || raw.totalReviewCount || raw.reviewCnt || 0,
          category: raw.category1Name || raw.categoryName || raw.dispCategoryName || raw.category || '',
          productUrl: raw.mallProductUrl || raw.crUrl || raw.productUrl || raw.link || '',
          productId: raw.id || raw.nvMid || raw.productId || raw.nid || '',
          image: raw.imageUrl || raw.thumbnailUrl || raw.image || raw.imgUrl || '',
          maker: raw.maker || raw.manufacturer || '',
          brand: raw.brand || raw.brandName || '',
        };
      };

      const findShopItems = (obj, depth = 0) => {
        if (depth > 25 || !obj) return null;
        if (Array.isArray(obj) && obj.length > 2) {
          const first = obj[0]?.item || obj[0];
          if (first && typeof first === 'object') {
            const hasProductField = first.productName || first.productTitle || first.dispName || 
              (first.mallName && (first.price || first.lowPrice));
            if (hasProductField) {
              const filtered = obj.filter(item => {
                const raw = item?.item || item;
                return !isAd(raw) && !isAd(item);
              });
              if (filtered.length > 0) return filtered;
            }
          }
        }
        if (typeof obj === 'object' && !Array.isArray(obj)) {
          for (const k of Object.keys(obj)) {
            if (/^(ad|ads|adBanner|sponsored|powerlink)/i.test(k)) continue;
            const f = findShopItems(obj[k], depth + 1);
            if (f && f.length > 2) return f;
          }
        }
        return null;
      };

      // ══════════════════════════════════════════════════
      // 1차: 네이버 통합검색 쇼핑탭 (search.naver.com?where=shp)
      //   일반 검색이라 봇 감지가 search.shopping.naver.com보다 약함
      //   Referer: www.naver.com (네이버 메인에서 검색)
      // ══════════════════════════════════════════════════
      for (let attempt = 0; attempt < 3 && !success; attempt++) {
        try {
          const agent = getProxyAgent();
          const ua = randomUA();
          // 네이버 통합검색 쇼핑탭 - pagingIndex 또는 start 파라미터
          const shpUrl = `https://search.naver.com/search.naver?where=shp&query=${encodeURIComponent(keyword)}&pagingIndex=${page}&pagingSize=${ITEMS_PER_PAGE}&viewType=list&sort=rel&frm=NVSHSRC`;
          const sRes = await axios.get(shpUrl, {
            httpsAgent: agent, timeout: 20000, maxRedirects: 5,
            headers: {
              'User-Agent': ua,
              'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
              'Accept-Language': 'ko-KR,ko;q=0.9,en-US;q=0.8,en;q=0.7',
              'Accept-Encoding': 'gzip, deflate, br',
              'Referer': page === 1 ? 'https://www.naver.com/' : `https://search.naver.com/search.naver?where=shp&query=${encodeURIComponent(keyword)}`,
              'Sec-Fetch-Dest': 'document',
              'Sec-Fetch-Mode': 'navigate',
              'Sec-Fetch-Site': page === 1 ? 'same-site' : 'same-origin',
              'Sec-Fetch-User': '?1',
              'Upgrade-Insecure-Requests': '1',
              'Connection': 'keep-alive',
              ...(warmupCookies ? { 'Cookie': warmupCookies } : {}),
            }
          });
          const html = sRes.data;
          const htmlLen = typeof html === 'string' ? html.length : 0;

          // ── 통합검색 쇼핑탭 파싱 (광고 제외, 실제 상품만) ──

          // 방법 A: script 태그 내 JSON 블록들 전체 스캔
          const scriptBlocks = [...html.matchAll(/<script[^>]*>([\s\S]*?)<\/script>/g)];
          for (const block of scriptBlocks) {
            if (success) break;
            const scriptContent = block[1];
            if (!scriptContent || scriptContent.length < 500) continue;
            
            // JSON 객체 패턴 찾기 (다양한 임베딩 방식)
            const jsonPatterns = [
              /entry\.bootstrap\s*\([^,]*,\s*(\{[\s\S]*\})\s*\)\s*;?\s*$/,
              /__NEXT_DATA__[^>]*>\s*(\{[\s\S]*\})\s*$/,
              /window\.__.*?=\s*(\{[\s\S]*\})\s*;?\s*$/,
              /data\s*=\s*(\{[\s\S]*\})\s*;?\s*$/,
            ];
            
            for (const pat of jsonPatterns) {
              if (success) break;
              const m = scriptContent.match(pat);
              if (!m) continue;
              try {
                const jsonData = JSON.parse(m[1]);
                const items = findShopItems(jsonData);
                if (items && items.length > 0) {
                  products = items.map(extractProduct).filter(Boolean);
                  if (products.length > 0) {
                    success = true;
                    console.log(`  [통합검색JSON] 페이지 ${page}: ${products.length}건 ✓`);
                  }
                }
              } catch (e) { /* JSON 파싱 실패 - 다음 패턴 시도 */ }
            }
          }

          // 방법 B: 순서 기반 매칭 (productName + mallName + price 각각 전체 추출 후 인덱스 매칭)
          // 네이버 통합검색은 상품 데이터가 중첩 JSON 구조로 productName과 mallName이 다른 레벨에 있음
          // 하지만 HTML 내에서 같은 상품의 데이터는 순서가 보장됨
          if (!success) {
            const allNames = [...html.matchAll(/"productName"\s*:\s*"([^"]{2,200})"/g)];
            const allNameOrgs = [...html.matchAll(/"productNameOrg"\s*:\s*"([^"]{2,200})"/g)];
            const allMalls = [...html.matchAll(/"mallName"\s*:\s*"([^"]{1,100})"/g)];
            const allPrices = [...html.matchAll(/"(?:price|lowPrice|salePrice)"\s*:\s*"?(\d+)"?/g)];
            const allCats = [...html.matchAll(/"category(?:1Name|Name)"\s*:\s*"([^"]{1,50})"/g)];
            const allBrands = [...html.matchAll(/"brand"\s*:\s*"([^"]{1,80})"/g)];
            const allIds = [...html.matchAll(/"(?:nvMid|id)"\s*:\s*"?(\d{5,20})"?/g)];
            
            // ★ URL 관련 필드 전체 스캔
            const allMallUrls = [...html.matchAll(/"mallProductUrl"\s*:\s*"([^"]{10,500})"/g)];
            const allCrUrls = [...html.matchAll(/"crUrl"\s*:\s*"([^"]{10,500})"/g)];
            const allLinks = [...html.matchAll(/"link"\s*:\s*"([^"]{10,500})"/g)];
            // smartstore URL 직접 스캔
            const allStoreUrls = [...html.matchAll(/smartstore\.naver\.com\/([a-zA-Z0-9][a-zA-Z0-9_-]{1,50})(?:\/products)?/g)];
            
            console.log(`    [매칭분석] names=${allNames.length} malls=${allMalls.length} prices=${allPrices.length} mallUrls=${allMallUrls.length} crUrls=${allCrUrls.length} storeUrls=${allStoreUrls.length}`);
            
            // 첫 페이지 첫 시도에서 URL 필드 샘플 출력
            if (page === 1 && attempt === 0 && allNames.length > 0) {
              const samplePos = allNames[0].index;
              const urlCtx = html.substring(Math.max(0, samplePos - 200), Math.min(html.length, samplePos + 3000));
              // URL 관련 키 전체 스캔
              const urlKeys = [...urlCtx.matchAll(/"([a-zA-Z]*(?:url|Url|URL|link|Link|href|Href)[a-zA-Z]*)"\s*:\s*"([^"]{5,200})"/gi)];
              if (urlKeys.length > 0) {
                console.log(`    [URL필드] 첫 상품 주변 URL키들:`);
                urlKeys.slice(0, 10).forEach(uk => console.log(`      ${uk[1]}="${uk[2].substring(0, 100)}"`));
              } else {
                console.log(`    [URL필드] 첫 상품 주변에 URL 키 없음`);
              }
            }
            
            if (allNames.length > 0) {
              // mallName이 productName보다 많거나 같으면 순서 매칭 가능
              // 광고 필터: adId 근처(±500바이트)의 productName은 제외
              const adPositions = [...html.matchAll(/"adId"\s*:/g)].map(m => m.index);
              
              let mallIdx = 0;
              let priceIdx = 0;
              
              for (let i = 0; i < allNames.length; i++) {
                const namePos = allNames[i].index;
                
                // 광고 근처인지 확인
                const isNearAd = adPositions.some(adPos => Math.abs(adPos - namePos) < 800);
                if (isNearAd) continue;
                
                const rawName = allNames[i][1];
                const pName = cleanName(rawName);
                if (!pName || pName.length < 2) continue;
                if (/^(파워링크|광고|AD|sponsored)/i.test(pName)) continue;
                
                // 이 productName 다음에 오는 가장 가까운 mallName 찾기
                let closestMall = '';
                for (let mi = mallIdx; mi < allMalls.length; mi++) {
                  if (allMalls[mi].index > namePos) {
                    closestMall = allMalls[mi][1];
                    mallIdx = mi + 1;
                    break;
                  }
                }
                
                // 가장 가까운 price 찾기
                let closestPrice = '';
                for (let pi = priceIdx; pi < allPrices.length; pi++) {
                  if (allPrices[pi].index > namePos) {
                    closestPrice = allPrices[pi][1];
                    priceIdx = pi + 1;
                    break;
                  }
                }
                
                // 주변 5000바이트에서 카테고리/브랜드/URL 찾기
                const wideCtx = html.substring(Math.max(0, namePos - 500), Math.min(html.length, namePos + 5000));
                const catM = wideCtx.match(/"category(?:1Name|Name)"\s*:\s*"([^"]{1,50})"/);
                const brandM = wideCtx.match(/"brand"\s*:\s*"([^"]{1,80})"/);
                const idM = wideCtx.match(/"nvMid"\s*:\s*"?(\d{5,20})"?/);
                const imgM = wideCtx.match(/"imageUrl"\s*:\s*"([^"]{10,500})"/);
                const reviewM = wideCtx.match(/"reviewCount"\s*:\s*"?(\d+)"?/);
                // ★ pcUrl 우선 (통합검색 실제 필드명, \u002F 이스케이프)
                const pcUrlM = wideCtx.match(/"pcUrl"\s*:\s*"([^"]{10,500})"/);
                const urlM = wideCtx.match(/"mallProductUrl"\s*:\s*"([^"]{10,500})"/);
                const crUrlM = wideCtx.match(/"crUrl"\s*:\s*"([^"]{10,500})"/);
                const linkM = wideCtx.match(/"link"\s*:\s*"([^"]{10,500})"/);
                // \u002F → / 디코딩
                const dUrl = (u) => u ? u.replace(/\\u002F/g, '/').replace(/\\u003A/g, ':') : '';
                const extractedUrl = dUrl(pcUrlM?.[1] || urlM?.[1] || crUrlM?.[1] || linkM?.[1] || '');
                // slug 추출 (디코딩된 URL에서, 또는 outlink URL에서)
                let extractedSlug = '';
                if (extractedUrl) {
                  // outlink URL 패턴: url=https%3A%2F%2Fsmartstore.naver.com%2F{slug}
                  const outlinkM = extractedUrl.match(/url=https?%3A%2F%2F(?:m\.)?smartstore\.naver\.com%2F([a-zA-Z0-9][a-zA-Z0-9_-]{1,50})/);
                  if (outlinkM && outlinkM[1] !== 'main' && outlinkM[1] !== 'inflow') {
                    extractedSlug = outlinkM[1];
                  }
                  if (!extractedSlug) {
                    const directM = extractedUrl.match(/smartstore\.naver\.com\/([a-zA-Z0-9][a-zA-Z0-9_-]{1,50})/);
                    if (directM && directM[1] !== 'main' && directM[1] !== 'inflow') {
                      extractedSlug = directM[1];
                    }
                  }
                }
                // 폴백: wideCtx 전체에서 outlink URL 패턴 스캔
                if (!extractedSlug) {
                  const decodedCtx = dUrl(wideCtx);
                  const outlinkCtx = decodedCtx.match(/url=https?%3A%2F%2F(?:m\.)?smartstore\.naver\.com%2F([a-zA-Z0-9][a-zA-Z0-9_-]{1,50})/);
                  if (outlinkCtx && outlinkCtx[1] !== 'main' && outlinkCtx[1] !== 'inflow') {
                    extractedSlug = outlinkCtx[1];
                  }
                  if (!extractedSlug) {
                    const anySlug = decodedCtx.match(/smartstore\.naver\.com\/([a-zA-Z0-9][a-zA-Z0-9_-]{1,50})(?:\/|"|$)/);
                    if (anySlug && anySlug[1] !== 'main' && anySlug[1] !== 'inflow' && anySlug[1] !== 'products') {
                      extractedSlug = anySlug[1];
                    }
                  }
                }
                
                products.push({
                  productName: pName,
                  storeName: closestMall,
                  price: closestPrice,
                  reviewCount: reviewM ? parseInt(reviewM[1]) : 0,
                  category: catM?.[1] || '',
                  productUrl: extractedUrl,
                  productId: idM?.[1] || '',
                  image: imgM?.[1]?.replace(/\\u002F/g, '/') || '',
                  maker: '',
                  brand: brandM?.[1] || '',
                  sellerTel: '', sellerCeo: '',
                  storeSlug: extractedSlug,
                });
              }
              
              if (products.length > 0) {
                success = true;
                console.log(`  [통합검색순서매칭] 페이지 ${page}: ${products.length}건 ✓ (names=${allNames.length} malls=${allMalls.length})`);
              }
            }
          }

          // 방법 C: productNameOrg 폴백 (productName이 없는 경우)
          if (!success) {
            const orgNames = [...html.matchAll(/"productNameOrg"\s*:\s*"([^"]{2,200})"/g)];
            const orgMalls = [...html.matchAll(/"mallName"\s*:\s*"([^"]{1,100})"/g)];
            const orgPrices = [...html.matchAll(/"(?:price|lowPrice)"\s*:\s*"?(\d+)"?/g)];
            if (orgNames.length > 0) {
              for (let j = 0; j < orgNames.length; j++) {
                const pName = cleanName(orgNames[j]?.[1]);
                if (!pName || pName.length < 2) continue;
                products.push({
                  productName: pName, storeName: orgMalls[j]?.[1] || '',
                  price: orgPrices[j]?.[1] || '', reviewCount: 0, category: '',
                  productUrl: '', productId: '', image: '', maker: '', brand: '',
                });
              }
              if (products.length > 0) {
                success = true;
                console.log(`  [통합검색NameOrg] 페이지 ${page}: ${products.length}건 ✓`);
              }
            }
          }

          if (!success) {
            console.log(`  [통합검색] 페이지 ${page} 시도${attempt + 1}: 200 but no data (html: ${htmlLen}bytes)`);
            // 디버그: HTML에 어떤 키워드가 있는지 확인
            const hasProductTitle = html.includes('productTitle');
            const hasDispName = html.includes('dispName');
            const hasMallName = html.includes('mallName');
            const hasShoppingSection = html.includes('shp_') || html.includes('_shopping_');
            const hasAdId = html.includes('adId');
            console.log(`    디버그: productTitle=${hasProductTitle} dispName=${hasDispName} mallName=${hasMallName} shopping=${hasShoppingSection} adId=${hasAdId}`);
            
            // 페이지 1, 시도 1일 때만 상세 디버그 (mallName 주변 컨텍스트)
            if (page === 1 && attempt === 0) {
              // mallName 주변 500바이트 샘플 (최대 3개)
              const mallIdx = html.indexOf('"mallName"');
              if (mallIdx > -1) {
                const sample = html.substring(Math.max(0, mallIdx - 200), Math.min(html.length, mallIdx + 300));
                console.log(`    [샘플] mallName 주변: ${sample.substring(0, 400)}`);
              }
              // "name" 또는 "title" 포함된 JSON 키 전체 스캔
              const keyPatterns = [...html.matchAll(/"([a-zA-Z]*(?:name|title|Name|Title)[a-zA-Z]*)"\s*:\s*"([^"]{5,80})"/g)];
              const uniqueKeys = new Map();
              for (const m of keyPatterns) {
                if (!uniqueKeys.has(m[1]) && uniqueKeys.size < 20) {
                  uniqueKeys.set(m[1], m[2].substring(0, 50));
                }
              }
              if (uniqueKeys.size > 0) {
                console.log(`    [필드목록] ${[...uniqueKeys.entries()].map(([k,v]) => `${k}="${v}"`).join(' | ')}`);
              }
              // script 태그 내 JSON 크기 분석
              const scripts = [...html.matchAll(/<script[^>]*>([\s\S]*?)<\/script>/g)];
              const bigScripts = scripts.filter(s => s[1].length > 10000).map(s => s[1].length);
              console.log(`    [스크립트] 총 ${scripts.length}개, 10KB+: ${bigScripts.length}개 (크기: ${bigScripts.slice(0,5).join(', ')})`);
            }
          }
        } catch (e) {
          console.log(`  [통합검색] 페이지 ${page} 시도${attempt + 1}: ${e.response?.status || e.message}`);
          await sleep(1500 + attempt * 1500);
        }
      }

      // ══════════════════════════════════════════════════
      // 2차: 모바일 통합검색 쇼핑 (m.search.naver.com)
      //   모바일은 봇 감지가 더 약함
      // ══════════════════════════════════════════════════
      if (!success) {
        for (let attempt = 0; attempt < 2 && !success; attempt++) {
          try {
            const agent = getProxyAgent();
            const mUrl = `https://m.search.naver.com/search.naver?where=shm_shp&query=${encodeURIComponent(keyword)}&start=${startIdx}&display=${ITEMS_PER_PAGE}`;
            const mRes = await axios.get(mUrl, {
              httpsAgent: agent, timeout: 20000, maxRedirects: 5,
              headers: {
                'User-Agent': 'Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1',
                'Accept': 'text/html,application/xhtml+xml',
                'Accept-Language': 'ko-KR,ko;q=0.9',
                'Referer': 'https://m.naver.com/',
                'Sec-Fetch-Dest': 'document',
                'Sec-Fetch-Mode': 'navigate',
              }
            });
            const mHtml = mRes.data;

            // 모바일 통합검색 파싱 - 순서 기반 매칭 (PC와 동일)
            const mNames = [...mHtml.matchAll(/"productName"\s*:\s*"([^"]{2,200})"/g)];
            const mMalls = [...mHtml.matchAll(/"mallName"\s*:\s*"([^"]{1,100})"/g)];
            const mPrices = [...mHtml.matchAll(/"(?:price|lowPrice|salePrice)"\s*:\s*"?(\d+)"?/g)];
            
            if (mNames.length > 0) {
              const mAdPos = [...mHtml.matchAll(/"adId"\s*:/g)].map(m => m.index);
              let mMallIdx = 0, mPriceIdx = 0;
              
              for (let i = 0; i < mNames.length; i++) {
                const namePos = mNames[i].index;
                const isNearAd = mAdPos.some(ap => Math.abs(ap - namePos) < 800);
                if (isNearAd) continue;
                const pName = cleanName(mNames[i][1]);
                if (!pName || pName.length < 2) continue;
                if (/^(파워링크|광고|AD|sponsored)/i.test(pName)) continue;
                
                let mall = '';
                for (let mi = mMallIdx; mi < mMalls.length; mi++) {
                  if (mMalls[mi].index > namePos) { mall = mMalls[mi][1]; mMallIdx = mi + 1; break; }
                }
                let price = '';
                for (let pi = mPriceIdx; pi < mPrices.length; pi++) {
                  if (mPrices[pi].index > namePos) { price = mPrices[pi][1]; mPriceIdx = pi + 1; break; }
                }
                
                products.push({
                  productName: pName, storeName: mall, price: price,
                  reviewCount: 0, category: '', productUrl: '', productId: '',
                  image: '', maker: '', brand: '',
                });
              }
              if (products.length > 0) {
                success = true;
                console.log(`  [모바일순서매칭] 페이지 ${page}: ${products.length}건 ✓`);
              }
            }

            // JSON 재귀 탐색 폴백
            if (!success) {
              const scriptBlks = [...mHtml.matchAll(/<script[^>]*>([\s\S]*?)<\/script>/g)];
              for (const blk of scriptBlks) {
                if (success) break;
                const sc = blk[1];
                if (!sc || sc.length < 500) continue;
                const jsonPats = [
                  /entry\.bootstrap\s*\([^,]*,\s*(\{[\s\S]*\})\s*\)\s*;?\s*$/,
                  /window\.__.*?=\s*(\{[\s\S]*\})\s*;?\s*$/,
                ];
                for (const p of jsonPats) {
                  const mm = sc.match(p);
                  if (!mm) continue;
                  try {
                    const jd = JSON.parse(mm[1]);
                    const items = findShopItems(jd);
                    if (items && items.length > 0) {
                      products = items.map(extractProduct).filter(Boolean);
                      if (products.length > 0) {
                        success = true;
                        console.log(`  [모바일JSON] 페이지 ${page}: ${products.length}건 ✓`);
                        break;
                      }
                    }
                  } catch (e) {}
                }
              }
            }

            if (!success) console.log(`  [모바일통합] 페이지 ${page} 시도${attempt + 1}: no data (${mHtml.length}bytes)`);
          } catch (e) {
            console.log(`  [모바일통합] 페이지 ${page} 시도${attempt + 1}: ${e.response?.status || e.message}`);
            await sleep(2000 + attempt * 2000);
          }
        }
      }

      // ══════════════════════════════════════════════════
      // 3차: 네이버 쇼핑 모바일 (msearch.shopping.naver.com)
      //   마지막 시도 - 모바일 쇼핑
      // ══════════════════════════════════════════════════
      if (!success) {
        try {
          const agent = getProxyAgent();
          const msUrl = `https://msearch.shopping.naver.com/search/all?query=${encodeURIComponent(keyword)}&pagingIndex=${page}&sort=rel`;
          const msRes = await axios.get(msUrl, {
            httpsAgent: agent, timeout: 20000,
            headers: {
              'User-Agent': 'Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1',
              'Accept': 'text/html', 'Accept-Language': 'ko-KR,ko;q=0.9',
              'Referer': 'https://m.shopping.naver.com/',
            }
          });
          const msHtml = msRes.data;
          const msTitles = [...msHtml.matchAll(/"(?:productName|productTitle)"\s*:\s*"([^"]{2,200})"/g)];
          const msMalls = [...msHtml.matchAll(/"mallName"\s*:\s*"([^"]{1,100})"/g)];
          const msPrices = [...msHtml.matchAll(/"(?:price|lowPrice)"\s*:\s*"?(\d+)"?/g)];
          if (msTitles.length > 0) {
            for (let j = 0; j < msTitles.length; j++) {
              const pn = cleanName(msTitles[j]?.[1] || '');
              if (!pn || pn.length < 2) continue;
              products.push({
                productName: pn, storeName: msMalls[j]?.[1] || '',
                price: msPrices[j]?.[1] || '', reviewCount: 0, category: '',
                productUrl: '', productId: '', image: '', maker: '', brand: '',
              });
            }
            success = true;
            console.log(`  [모바일쇼핑] 페이지 ${page}: ${products.length}건 ✓`);
          } else {
            console.log(`  ✗ 페이지 ${page}: 전체 실패`);
          }
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
      // 페이지 간 딜레이
      await sleep(800 + Math.random() * 800);
    }

    allProducts.sort((a, b) => a.rank - b.rank);

    // ══════════════════════════════════════════════════
    // 2단계: 판매자 정보 크롤링 (전화번호, 대표자명)
    // 각 상품의 스토어 페이지에서 판매자 정보 추출
    // ══════════════════════════════════════════════════
    console.log(`\n[2단계] 판매자 정보 크롤링 시작 (${allProducts.length}건)`);
    
    // 스토어별로 중복 제거 (같은 스토어는 한 번만 조회)
    const storeInfoCache = {};
    
    const fetchSellerInfo = async (product, idx) => {
      const { storeName, productUrl, productId, storeSlug: preSlug } = product;
      
      // 캐시 확인
      if (storeName && storeInfoCache[storeName]) {
        return storeInfoCache[storeName];
      }
      
      const result = { sellerTel: '', sellerCeo: '' };
      
      try {
        let storeSlug = preSlug || '';
        
        // productUrl에서 slug 추출
        if (!storeSlug && productUrl) {
          const slugM = productUrl.match(/smartstore\.naver\.com\/([a-zA-Z0-9][a-zA-Z0-9_-]{1,50})/);
          if (slugM) storeSlug = slugM[1];
        }
        
        if (idx < 3) console.log(`    [디버그#${idx}] preSlug="${preSlug||''}" slug="${storeSlug}" productId="${productId}"`);
        
        // 방법 1: nvMid로 네이버 쇼핑 카탈로그 페이지 (search.naver.com 경유 - 차단 약함)
        if (!storeSlug && productId) {
          try {
            const agent = getProxyAgent();
            // 네이버 통합검색에서 nvMid로 상품 정보 조회
            const catUrl = `https://search.naver.com/search.naver?where=shp&query=${productId}&nso=&pagingIndex=1&pagingSize=1`;
            const cRes = await axios.get(catUrl, {
              httpsAgent: agent, timeout: 15000, maxRedirects: 5,
              headers: { 'User-Agent': randomUA(), 'Accept-Language': 'ko-KR,ko;q=0.9', 'Referer': 'https://www.naver.com/' }
            });
            const cHtml = cRes.data || '';
            const slugM2 = cHtml.match(/smartstore\.naver\.com\/([a-zA-Z0-9][a-zA-Z0-9_-]{1,50})/);
            if (slugM2 && slugM2[1] !== 'main') storeSlug = slugM2[1];
            if (idx < 3) console.log(`    [디버그#${idx}] 카탈로그검색: ${cRes.status} slug=${storeSlug}`);
          } catch (e) {
            if (idx < 3) console.log(`    [디버그#${idx}] 카탈로그 실패: ${e.response?.status || e.message}`);
          }
        }
        
        if (!storeSlug || storeSlug === 'main' || storeSlug === 'inflow') {
          if (idx < 3) console.log(`    [디버그#${idx}] slug 없음 → 스킵`);
          return result;
        }
        
        // 방법 2: 스토어 메인 페이지 접속 → 판매자 정보 HTML 추출
        try {
          const agent = getProxyAgent();
          const storeUrl = `https://smartstore.naver.com/${storeSlug}`;
          const sRes = await axios.get(storeUrl, {
            httpsAgent: agent, timeout: 15000, maxRedirects: 5,
            headers: {
              'User-Agent': randomUA(),
              'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
              'Accept-Language': 'ko-KR,ko;q=0.9',
              'Referer': 'https://search.naver.com/',
            }
          });
          const sHtml = sRes.data || '';
          if (idx < 3) console.log(`    [디버그#${idx}] 스토어: ${sRes.status} ${sHtml.length}bytes`);
          
          // 전화번호 추출
          const telM = sHtml.match(/"(?:tel|phoneNumber|csPhoneNumber|customerCenterTel|representTelNo)"\s*:\s*"([0-9][0-9\-]{5,20})"/);
          if (telM) result.sellerTel = telM[1];
          
          // 대표자 추출
          const ceoM = sHtml.match(/"(?:representative|representativeName|ceoName|ownerName)"\s*:\s*"([^"]{1,50})"/);
          if (ceoM) result.sellerCeo = ceoM[1];
          
          if (idx < 3) console.log(`    [디버그#${idx}] HTML직접: tel="${result.sellerTel}" ceo="${result.sellerCeo}"`);
          
          // channelUid로 API 시도
          if (!result.sellerTel) {
            const uidM = sHtml.match(/"channelUid"\s*:\s*"([a-zA-Z0-9_-]+)"/);
            const chNoM = sHtml.match(/"channelNo"\s*:\s*"?(\d+)"?/);
            if (idx < 3) console.log(`    [디버그#${idx}] uid=${uidM?.[1]||'X'} chNo=${chNoM?.[1]||'X'}`);
            
            if (uidM || chNoM) {
              try {
                const agent2 = getProxyAgent();
                const id = chNoM?.[1] || uidM[1];
                const infoUrl = `https://smartstore.naver.com/i/v1/stores/${id}/seller-info`;
                const iRes = await axios.get(infoUrl, {
                  httpsAgent: agent2, timeout: 10000,
                  headers: { 'User-Agent': randomUA(), 'Accept': 'application/json', 'Referer': storeUrl }
                });
                const info = iRes.data;
                if (idx < 3) console.log(`    [디버그#${idx}] API: ${iRes.status} keys=${Object.keys(info||{}).slice(0,10).join(',')}`);
                if (info) {
                  result.sellerTel = info.tel || info.phone || info.csPhoneNumber || info.customerCenterTel || info.representTelNo || '';
                  result.sellerCeo = info.representative || info.representativeName || info.ceoName || info.ownerName || '';
                }
              } catch (e) {
                if (idx < 3) console.log(`    [디버그#${idx}] API실패: ${e.response?.status || e.message}`);
              }
            }
            
            // 최후: __NEXT_DATA__ 안에서 seller 관련 키 전부 덤프
            if (idx < 3 && !result.sellerTel) {
              const nextDataM = sHtml.match(/__NEXT_DATA__[^>]*>\s*(\{[\s\S]*?\})\s*<\/script/);
              if (nextDataM) {
                console.log(`    [디버그#${idx}] __NEXT_DATA__ 발견 (${nextDataM[1].length}bytes)`);
                const sellerKeys = [...nextDataM[1].matchAll(/"([^"]*(?:seller|tel|phone|ceo|representative|owner|Tel|Phone)[^"]*)"\s*:\s*"([^"]{1,100})"/gi)];
                sellerKeys.slice(0, 15).forEach(sk => console.log(`      ${sk[1]}="${sk[2]}"`));
              } else {
                // script 태그 전체에서 tel/phone 키 찾기
                const anyTel = [...sHtml.matchAll(/"([^"]*(?:tel|phone|Tel|Phone)[^"]*)"\s*:\s*"([^"]{3,30})"/g)];
                const anyCeo = [...sHtml.matchAll(/"([^"]*(?:representative|ceo|owner|CEO|Owner)[^"]*)"\s*:\s*"([^"]{1,50})"/gi)];
                console.log(`    [디버그#${idx}] tel키=${anyTel.length}개 ceo키=${anyCeo.length}개`);
                anyTel.slice(0, 5).forEach(t => console.log(`      ${t[1]}="${t[2]}"`));
                anyCeo.slice(0, 5).forEach(c => console.log(`      ${c[1]}="${c[2]}"`));
              }
            }
          }
        } catch (e) {
          if (idx < 3) console.log(`    [디버그#${idx}] 스토어접속 실패: ${e.response?.status || e.message}`);
          
          // 스토어 직접 접속 실패(490) → store.naver.com 경유
          if (e.response?.status === 490 || e.response?.status === 403) {
            try {
              const agent3 = getProxyAgent();
              const altUrl = `https://m.smartstore.naver.com/${storeSlug}`;
              const mRes = await axios.get(altUrl, {
                httpsAgent: agent3, timeout: 15000, maxRedirects: 5,
                headers: { 'User-Agent': 'Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1', 'Accept-Language': 'ko-KR,ko;q=0.9', 'Referer': 'https://m.search.naver.com/' }
              });
              const mHtml = mRes.data || '';
              if (idx < 3) console.log(`    [디버그#${idx}] 모바일스토어: ${mRes.status} ${mHtml.length}bytes`);
              const mTel = mHtml.match(/"(?:tel|phoneNumber|csPhoneNumber|customerCenterTel|representTelNo)"\s*:\s*"([0-9][0-9\-]{5,20})"/);
              const mCeo = mHtml.match(/"(?:representative|representativeName|ceoName|ownerName)"\s*:\s*"([^"]{1,50})"/);
              if (mTel) result.sellerTel = mTel[1];
              if (mCeo) result.sellerCeo = mCeo[1];
            } catch (e2) {
              if (idx < 3) console.log(`    [디버그#${idx}] 모바일도 실패: ${e2.response?.status || e2.message}`);
            }
          }
        }
        
        if (idx < 3) console.log(`    [디버그#${idx}] 최종: tel="${result.sellerTel}" ceo="${result.sellerCeo}"`);
        
      } catch (e) {
        if (idx < 3) console.log(`    [디버그#${idx}] 전체실패: ${e.response?.status || e.message}`);
      }
      
      if (storeName) storeInfoCache[storeName] = result;
      return result;
    };
    
    // 병렬 처리 (5개씩 배치)
    const BATCH_SIZE = 5;
    for (let bi = 0; bi < allProducts.length; bi += BATCH_SIZE) {
      const batch = allProducts.slice(bi, bi + BATCH_SIZE);
      const results = await Promise.all(batch.map((p, j) => fetchSellerInfo(p, bi + j)));
      for (let j = 0; j < batch.length; j++) {
        batch[j].sellerTel = results[j].sellerTel;
        batch[j].sellerCeo = results[j].sellerCeo;
      }
      if (bi + BATCH_SIZE < allProducts.length) await sleep(500);
      if ((bi + BATCH_SIZE) % 20 === 0) {
        const filled = allProducts.filter(p => p.sellerTel).length;
        console.log(`  [판매자정보] ${Math.min(bi + BATCH_SIZE, allProducts.length)}/${allProducts.length} 처리 (전화번호 ${filled}건)`);
      }
    }
    
    const filledCount = allProducts.filter(p => p.sellerTel).length;
    console.log(`[2단계] 판매자 정보 완료: ${filledCount}/${allProducts.length}건 전화번호 확보`);

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
