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

// 관리자 계정
const adminExists = db.prepare('SELECT id FROM users WHERE username = ?').get('admin');
if (!adminExists) {
  const hashedPw = bcrypt.hashSync('admin1234', 10);
  db.prepare('INSERT INTO users (username, password, points, is_admin) VALUES (?, ?, ?, ?)').run('admin', hashedPw, 1000000, 1);
  console.log('관리자 계정 생성됨 - admin / admin1234 (1,000,000P)');
}

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));

// ============================================================
// 프록시 설정 - 10,000개 IP 회전
// ============================================================
const PROXY_URL = process.env.PROXY_URL; // http://user:pass@kr.decodo.com:10001

const usedPorts = new Set();
function getProxyAgent() {
  if (!PROXY_URL) return null;

  const url = new URL(PROXY_URL);
  const basePort = parseInt(url.port) || 10001;

  // 10001 ~ 20000 범위에서 미사용 포트 선택
  if (usedPorts.size > 9000) usedPorts.clear();
  let port;
  do {
    port = basePort + Math.floor(Math.random() * 10000);
  } while (usedPorts.has(port));
  usedPorts.add(port);
  url.port = String(port);

  return new HttpsProxyAgent(url.toString());
}

// User-Agent 풀 (10개)
const UA_LIST = [
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36',
  'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36',
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36',
  'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36',
  'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.1 Safari/605.1.15',
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:133.0) Gecko/20100101 Firefox/133.0',
  'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:132.0) Gecko/20100101 Firefox/132.0',
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36',
  'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36',
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.6778.86 Safari/537.36',
];
function randomUA() { return UA_LIST[Math.floor(Math.random() * UA_LIST.length)]; }
function sleep(ms) { return new Promise(r => setTimeout(r, ms)); }

// ============================================================
// JWT 인증
// ============================================================
function requireLogin(req, res, next) {
  const token = req.cookies.token || req.headers.authorization?.replace('Bearer ', '');
  if (!token) return res.status(401).json({ error: '로그인이 필요합니다.' });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch { return res.status(401).json({ error: '유효하지 않은 토큰입니다.' }); }
}

// ============================================================
// 인증 API
// ============================================================
app.post('/api/login', (req, res) => {
  const { username, password } = req.body;
  const user = db.prepare('SELECT * FROM users WHERE username = ?').get(username);
  if (!user || !bcrypt.compareSync(password, user.password))
    return res.status(401).json({ error: '아이디 또는 비밀번호가 올바르지 않습니다.' });
  const token = jwt.sign({ userId: user.id, username: user.username, isAdmin: user.is_admin }, JWT_SECRET, { expiresIn: '7d' });
  res.cookie('token', token, { httpOnly: true, maxAge: 7 * 24 * 60 * 60 * 1000 });
  res.json({ success: true, token, user: { id: user.id, username: user.username, points: user.points, isAdmin: user.is_admin } });
});

app.get('/api/me', requireLogin, (req, res) => {
  const user = db.prepare('SELECT id, username, points, is_admin as isAdmin FROM users WHERE id = ?').get(req.user.userId);
  res.json({ user });
});

app.post('/api/logout', (req, res) => {
  res.clearCookie('token');
  res.json({ success: true });
});

// 관리자 API
app.get('/api/admin/users', requireLogin, (req, res) => {
  if (!req.user.isAdmin) return res.status(403).json({ error: '권한 없음' });
  const users = db.prepare('SELECT id, username, points, is_admin, created_at FROM users').all();
  res.json({ users });
});

app.post('/api/admin/points', requireLogin, (req, res) => {
  if (!req.user.isAdmin) return res.status(403).json({ error: '권한 없음' });
  const { userId, amount, description } = req.body;
  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(userId);
  if (!user) return res.status(404).json({ error: '사용자 없음' });
  const newPts = user.points + amount;
  if (newPts < 0) return res.status(400).json({ error: '포인트가 부족합니다.' });
  db.prepare('UPDATE users SET points = ? WHERE id = ?').run(newPts, userId);
  db.prepare('INSERT INTO point_history (user_id, amount, type, description) VALUES (?, ?, ?, ?)').run(
    userId, amount, amount > 0 ? 'charge' : 'deduct', description || '관리자 조정'
  );
  res.json({ success: true, newPoints: newPts });
});

// ============================================================
// 쿠팡 크롤링 API - 2단계 (검색결과 + 판매자정보)
// ============================================================
app.post('/api/extract/coupang', requireLogin, async (req, res) => {
  const { keyword, startRank, endRank } = req.body;
  if (!keyword) return res.status(400).json({ error: '키워드를 입력해주세요.' });

  const sr = parseInt(startRank) || 1;
  const er = Math.min(parseInt(endRank) || 50, 100); // 최대 100위
  const count = er - sr + 1;

  const user = db.prepare('SELECT points FROM users WHERE id = ?').get(req.user.userId);
  if (user.points < count) return res.status(400).json({ error: `포인트 부족 (필요: ${count}P, 보유: ${user.points}P)` });

  console.log(`\n${'='.repeat(60)}`);
  console.log(`쿠팡 크롤링: "${keyword}" (${sr}~${er}위)`);
  console.log(`${'='.repeat(60)}`);

  try {
    const ITEMS_PER_PAGE = 36;
    const totalPages = Math.ceil(er / ITEMS_PER_PAGE) + 1;
    const allProducts = [];
    const existingRanks = new Set();

    // ──────────────────────────────────────────
    // 1단계: 쿠팡 검색결과 크롤링
    // ──────────────────────────────────────────
    for (let page = 1; page <= totalPages && allProducts.length < count; page++) {
      let success = false;
      let retries = 0;

      while (!success && retries < 3) {
        try {
          const searchUrl = `https://www.coupang.com/np/search?q=${encodeURIComponent(keyword)}&channel=user&component=&eventCategory=SRP&trcid=&traid=&sorter=scoreDesc&minPrice=&maxPrice=&priceRange=&filterType=&listSize=${ITEMS_PER_PAGE}&filter=&isPriceRange=false&brand=&offerCondition=&rating=0&page=${page}&rocketAll=false&searchIndexingToken=&backgroundColor=`;

          const agent = getProxyAgent();
          const ua = randomUA();

          const sRes = await axios.get(searchUrl, {
            ...(agent ? { httpsAgent: agent } : {}),
            timeout: 20000,
            headers: {
              'User-Agent': ua,
              'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
              'Accept-Language': 'ko-KR,ko;q=0.9,en;q=0.3',
              'Accept-Encoding': 'gzip, deflate, br',
              'Referer': page === 1 ? 'https://www.coupang.com/' : `https://www.coupang.com/np/search?q=${encodeURIComponent(keyword)}`,
              'Connection': 'keep-alive',
              'Upgrade-Insecure-Requests': '1',
            },
            maxRedirects: 5,
          });

          const html = typeof sRes.data === 'string' ? sRes.data : String(sRes.data);

          // 파싱: search-product 또는 baby-product
          const products = [];
          const itemRegex = /<li[^>]*class="[^"]*(?:search-product|baby-product)\b[^"]*"[^>]*>([\s\S]*?)<\/li>/gi;
          let itemMatch;

          while ((itemMatch = itemRegex.exec(html)) !== null) {
            const itemHtml = itemMatch[0];

            // 광고 제외
            if (itemHtml.includes('ad-badge') || itemHtml.includes('__ad') || itemHtml.includes('sponsored')) continue;

            // 상품명
            const nameM = itemHtml.match(/class="name"[^>]*>([^<]+)/) || itemHtml.match(/class="[^"]*name[^"]*"[^>]*>([^<]{3,200})/);
            if (!nameM) continue;
            const productName = nameM[1].trim();

            // 가격
            const priceM = itemHtml.match(/class="price-value"[^>]*>([^<]+)/) || itemHtml.match(/class="[^"]*price[^"]*"[^>]*>([0-9,]+)/);
            const price = priceM ? priceM[1].replace(/[^0-9]/g, '') : '';

            // 할인 전 가격
            const basePriceM = itemHtml.match(/class="base-price"[^>]*>([^<]+)/);
            const basePrice = basePriceM ? basePriceM[1].replace(/[^0-9]/g, '') : '';

            // 할인율
            const discountM = itemHtml.match(/class="[^"]*discount[^"]*"[^>]*>([^<]+)/);
            const discount = discountM ? discountM[1].trim() : '';

            // 별점
            const ratingM = itemHtml.match(/class="rating"[^>]*>([^<]+)/);
            const rating = ratingM ? ratingM[1].trim() : '';

            // 리뷰수
            const reviewM = itemHtml.match(/class="rating-total-count"[^>]*>\(?([^)<]+)\)?/);
            const reviewCount = reviewM ? parseInt(reviewM[1].replace(/[^0-9]/g, '')) || 0 : 0;

            // 상품 URL
            const urlM = itemHtml.match(/href="(\/vp\/products\/[^"]+)"/) || itemHtml.match(/href="(\/np\/[^"]+)"/);
            const productUrl = urlM ? 'https://www.coupang.com' + urlM[1] : '';

            // ID 추출
            const pidM = productUrl.match(/products\/(\d+)/);
            const vidM = productUrl.match(/vendorItemId=(\d+)/);
            const iidM = productUrl.match(/itemId=(\d+)/);

            // 이미지
            const imgM = itemHtml.match(/data-img-src="(https?:\/\/[^"]+)"/) || itemHtml.match(/src="(https?:\/\/[^"]*(?:coupangcdn|thumbnail)[^"]+)"/);
            const image = imgM ? imgM[1] : '';

            // 로켓배송
            const isRocket = /rocket|로켓/.test(itemHtml);

            products.push({
              productName, price, basePrice, discount, rating, reviewCount,
              productUrl, productId: pidM?.[1] || '', vendorItemId: vidM?.[1] || '', itemId: iidM?.[1] || '',
              image, isRocket,
              sellerName: '', sellerTel: '', sellerCeo: '', bizNo: '',
            });
          }

          if (products.length > 0) {
            success = true;
            console.log(`  [검색] 페이지 ${page}: ${products.length}건`);

            for (let j = 0; j < products.length && allProducts.length < count; j++) {
              const globalRank = (page - 1) * ITEMS_PER_PAGE + j + 1;
              if (globalRank < sr || globalRank > er || existingRanks.has(globalRank)) continue;
              existingRanks.add(globalRank);
              allProducts.push({ rank: globalRank, ...products[j] });
            }
          } else {
            // 디버그: 파싱 실패
            console.log(`  [디버그] 페이지 ${page}: 0건 (HTML ${html.length}자)`);

            // li 클래스 패턴
            const liClasses = [...html.matchAll(/<li[^>]*class="([^"]*)"[^>]*>/g)]
              .map(m => m[1]).filter(c => c.includes('product') || c.includes('baby'));
            if (liClasses.length) console.log(`  [디버그] li classes: ${[...new Set(liClasses)].slice(0, 5).join(', ')}`);

            // 상품명 패턴
            const namePatterns = [...html.matchAll(/class="([^"]*name[^"]*)"[^>]*>([^<]{5,80})/g)];
            if (namePatterns.length) console.log(`  [디버그] name 패턴: ${namePatterns.slice(0, 3).map(m => m[1]).join(', ')}`);

            // CAPTCHA 감지
            if (html.includes('CAPTCHA') || html.includes('보안문자') || html.includes('captcha')) {
              console.log(`  [차단] CAPTCHA 감지!`);
            }

            retries++;
            if (retries < 3) {
              console.log(`  → 재시도 ${retries}/3`);
              await sleep(2000);
            } else {
              success = true; // 3회 실패 → 다음 페이지로
            }
          }
        } catch (e) {
          console.log(`  [오류] 페이지 ${page}: ${e.message}`);
          retries++;
          if (retries < 3) await sleep(2000);
          else success = true;
        }
      }

      // 페이지 간 딜레이
      if (page < totalPages) await sleep(1000 + Math.random() * 1000);
    }

    console.log(`\n[1단계 완료] 검색결과 ${allProducts.length}건 수집`);

    if (allProducts.length === 0) {
      return res.status(400).json({ error: '검색 결과를 파싱할 수 없습니다. 키워드를 확인해주세요.' });
    }

    // ──────────────────────────────────────────
    // 2단계: 판매자 상세정보 크롤링
    // ──────────────────────────────────────────
    console.log(`\n[2단계] 판매자 정보 수집 시작: ${allProducts.length}건`);
    const sellerCache = {};

    for (let i = 0; i < allProducts.length; i++) {
      const p = allProducts[i];
      if (!p.productUrl) continue;

      try {
        const pAgent = getProxyAgent();
        const pRes = await axios.get(p.productUrl, {
          ...(pAgent ? { httpsAgent: pAgent } : {}),
          timeout: 15000,
          headers: {
            'User-Agent': randomUA(),
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'ko-KR,ko;q=0.9',
            'Referer': `https://www.coupang.com/np/search?q=${encodeURIComponent(keyword)}`,
            'Connection': 'keep-alive',
          },
          maxRedirects: 5,
        });

        const pHtml = typeof pRes.data === 'string' ? pRes.data : String(pRes.data);

        // 판매업체명 (다중 패턴)
        const sellerPatterns = [
          /class="[^"]*prod-vendor-name[^"]*"[^>]*>([^<]+)/,
          /판매업체[^<]*<[^>]*>([^<]+)/,
          /"vendorName"\s*:\s*"([^"]+)"/,
          /data-vendor-name="([^"]+)"/,
          /class="[^"]*vendor[^"]*"[^>]*>([^<]{2,50})/,
          /"sellerName"\s*:\s*"([^"]+)"/,
        ];
        for (const pat of sellerPatterns) {
          const m = pHtml.match(pat);
          if (m && m[1] && m[1].trim().length >= 2) { p.sellerName = m[1].trim(); break; }
        }

        // 캐시 확인
        if (p.sellerName && sellerCache[p.sellerName]) {
          const c = sellerCache[p.sellerName];
          p.sellerTel = c.sellerTel;
          p.sellerCeo = c.sellerCeo;
          p.bizNo = c.bizNo;
        } else {
          // 전화번호
          const telPatterns = [
            /(?:전화번호|연락처|고객센터)\s*[:：]?\s*([\d]{2,4}[-\s]?[\d]{3,4}[-\s]?[\d]{4})/,
            /"(?:tel|phoneNumber|csPhoneNumber|phone)"\s*:\s*"([\d][\d\-]{5,20})"/,
            /(?:cellNo|telNo|contactNumber)["']?\s*[:=]\s*["']?([\d][\d\-]{5,20})/,
          ];
          for (const pat of telPatterns) {
            const m = pHtml.match(pat);
            if (m && m[1]) { p.sellerTel = m[1].trim(); break; }
          }

          // 대표자
          const ceoPatterns = [
            /(?:대표자|대표이사|성명)\s*[:：]?\s*([가-힣]{2,5})/,
            /"(?:representative|ceoName|representativeName)"\s*:\s*"([^"]{1,50})"/,
          ];
          for (const pat of ceoPatterns) {
            const m = pHtml.match(pat);
            if (m && m[1]) { p.sellerCeo = m[1].trim(); break; }
          }

          // 사업자등록번호
          const bizPatterns = [
            /(?:사업자등록번호|사업자번호)\s*[:：]?\s*(\d{3}-\d{2}-\d{5})/,
            /(\d{3}-\d{2}-\d{5})/,
          ];
          for (const pat of bizPatterns) {
            const m = pHtml.match(pat);
            if (m && m[1]) { p.bizNo = m[1].trim(); break; }
          }

          // 캐시 저장
          if (p.sellerName) {
            sellerCache[p.sellerName] = { sellerTel: p.sellerTel, sellerCeo: p.sellerCeo, bizNo: p.bizNo };
          }
        }

        // 디버그 (첫 5건)
        if (i < 5) {
          console.log(`  [${i + 1}] ${pRes.status} ${pHtml.length}b | 판매자="${p.sellerName}" 전화="${p.sellerTel}" 대표="${p.sellerCeo}" 사업자="${p.bizNo}"`);

          if (!p.sellerName && !p.sellerTel) {
            const vendorKeys = [...pHtml.matchAll(/(?:vendor|seller|판매|업체|사업자)[^<]{0,100}/gi)];
            console.log(`    vendor 패턴: ${vendorKeys.length}건`);
            vendorKeys.slice(0, 3).forEach(v => console.log(`    "${v[0].substring(0, 80)}"`));

            const phones = [...pHtml.matchAll(/[\d]{2,4}-[\d]{3,4}-[\d]{4}/g)];
            console.log(`    전화번호 패턴: ${phones.length}건`);
            phones.slice(0, 3).forEach(ph => console.log(`    "${ph[0]}"`));
          }
        }
      } catch (e) {
        if (i < 5) console.log(`  [${i + 1}] 오류: ${e.message}`);
      }

      // 딜레이
      await sleep(500 + Math.random() * 500);

      // 진행률
      if ((i + 1) % 10 === 0 || i === allProducts.length - 1) {
        const filled = allProducts.filter(p => p.sellerName || p.sellerTel).length;
        console.log(`  [진행] ${i + 1}/${allProducts.length} (판매자 ${filled}건)`);
      }
    }

    // ──────────────────────────────────────────
    // 포인트 차감 & 응답
    // ──────────────────────────────────────────
    const successResults = allProducts.filter(r => r.productName);
    const used = successResults.length;
    const newPts = user.points - used;

    db.prepare('UPDATE users SET points = ? WHERE id = ?').run(newPts, req.user.userId);
    db.prepare('INSERT INTO point_history (user_id, amount, type, description) VALUES (?, ?, ?, ?)').run(
      req.user.userId, -used, 'use', `쿠팡: ${keyword} (${used}건)`
    );

    const withSeller = allProducts.filter(p => p.sellerName).length;
    const withTel = allProducts.filter(p => p.sellerTel).length;

    console.log(`\n[완료] ${allProducts.length}건 | 판매자 ${withSeller}건 | 전화번호 ${withTel}건`);
    console.log(`${'='.repeat(60)}\n`);

    res.json({
      success: true,
      data: allProducts,
      usedPoints: used,
      remainingPoints: newPts,
    });

  } catch (error) {
    console.error('쿠팡 에러:', error.message);
    res.status(500).json({ error: '데이터 추출 중 오류: ' + error.message });
  }
});

// ============================================================
// 포인트 히스토리 API
// ============================================================
app.get('/api/history/points', requireLogin, (req, res) => {
  const history = db.prepare(
    'SELECT * FROM point_history WHERE user_id = ? ORDER BY created_at DESC LIMIT 50'
  ).all(req.user.userId);
  res.json(history);
});

// ============================================================
// 서버 시작
// ============================================================
app.listen(PORT, () => {
  console.log(`서버 실행 중: http://localhost:${PORT}`);
});
