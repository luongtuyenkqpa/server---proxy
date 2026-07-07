/**
 * KeyVault Server — backend API + giao diện (index.js + package.json).
 * Chức năng chính: lưu/tải state dashboard (/api/state), xác thực key
 * cho app ngoài (/api/verify), trang bán key ("/") và dashboard quản
 * trị ("/admin"), thanh toán mua key, và GetKey (vượt link nhận key).
 * Chạy: node index.js (mặc định cổng 3000, đổi bằng PORT=xxxx).
 */

const http = require('http');
const https = require('https');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const PORT = process.env.PORT || 3000;
const DB_FILE = path.join(__dirname, 'db.json');

/* =====================================================================================
   BẢO MẬT PHÒNG THỦ (chỉ mang tính phòng thủ: giới hạn tốc độ request, chống dò mật khẩu,
   chống dữ liệu không hợp lệ gây sai số dư/khoá. KHÔNG chứa bất kỳ cơ chế chủ động "phản
   công", quét ngược, hay can thiệp vào máy của người gửi request — chỉ giới hạn/ghi log
   trên chính server này.
   ===================================================================================== */

/* Lấy IP thật của người gửi request, có tính tới việc chạy sau reverse-proxy (Render/CDN)
   vẫn dùng header x-forwarded-for nếu có, mặc định lấy IP socket trực tiếp. */
function getClientIP(req){
  const xf = req.headers['x-forwarded-for'];
  if(xf) return String(xf).split(',')[0].trim();
  return (req.socket && req.socket.remoteAddress) || 'unknown';
}

/* ---- Rate limiter đơn giản theo "cửa sổ trượt" (sliding window) lưu trong RAM ----
   Dùng cho các endpoint nhạy cảm (login, register, topup-request, checkout, verify...).
   Không lưu xuống DB vì chỉ cần tồn tại tạm thời trong bộ nhớ tiến trình. */
const rateLimitBuckets = new Map(); // key: `${scope}:${ip}` -> [timestamps]
function isRateLimited(scope, ip, maxRequests, windowMs){
  const key = scope + ':' + ip;
  const now = Date.now();
  let arr = rateLimitBuckets.get(key);
  if(!arr){ arr = []; rateLimitBuckets.set(key, arr); }
  // loại bỏ các mốc thời gian đã ra ngoài cửa sổ
  while(arr.length && now - arr[0] > windowMs) arr.shift();
  if(arr.length >= maxRequests){
    return true;
  }
  arr.push(now);
  return false;
}
// Dọn định kỳ các bucket rỗng/cũ để không rò rỉ bộ nhớ khi chạy lâu dài.
setInterval(()=>{
  const now = Date.now();
  for(const [key, arr] of rateLimitBuckets.entries()){
    while(arr.length && now - arr[0] > 15 * 60 * 1000) arr.shift();
    if(arr.length === 0) rateLimitBuckets.delete(key);
  }
}, 5 * 60 * 1000);

/* ---- Chống dò mật khẩu (brute-force) theo IP + theo username ----
   Sau nhiều lần đăng nhập/đăng ký sai liên tiếp, tạm khoá thêm request mới trong ít phút.
   Đây là khoá TẠM THỜI (tự hết hạn), không chặn IP vĩnh viễn, không phải "phản công". */
const failedAttempts = new Map(); // key: `${scope}:${ip|username}` -> { count, firstAt, lockedUntil }
const BRUTE_FORCE_MAX_ATTEMPTS = 6;      // số lần sai tối đa trong 1 cửa sổ
const BRUTE_FORCE_WINDOW_MS = 5 * 60 * 1000;   // cửa sổ tính số lần sai: 5 phút
const BRUTE_FORCE_LOCK_MS = 10 * 60 * 1000;    // thời gian khoá tạm sau khi vượt ngưỡng: 10 phút

function isLockedOut(scope, id){
  const rec = failedAttempts.get(scope + ':' + id);
  if(!rec) return false;
  if(rec.lockedUntil && rec.lockedUntil > Date.now()) return true;
  if(rec.lockedUntil && rec.lockedUntil <= Date.now()){
    failedAttempts.delete(scope + ':' + id); // hết hạn khoá, xoá luôn cho sạch
    return false;
  }
  return false;
}
function registerFailedAttempt(scope, id){
  const key = scope + ':' + id;
  const now = Date.now();
  let rec = failedAttempts.get(key);
  if(!rec || (now - rec.firstAt) > BRUTE_FORCE_WINDOW_MS){
    rec = { count: 0, firstAt: now, lockedUntil: 0 };
  }
  rec.count += 1;
  if(rec.count >= BRUTE_FORCE_MAX_ATTEMPTS){
    rec.lockedUntil = now + BRUTE_FORCE_LOCK_MS;
    console.warn(`[Security] Khoá tạm ${BRUTE_FORCE_LOCK_MS/60000} phút do sai quá nhiều lần: ${key}`);
  }
  failedAttempts.set(key, rec);
}
function clearFailedAttempts(scope, id){
  failedAttempts.delete(scope + ':' + id);
}
// Dọn định kỳ các bản ghi đã hết hạn từ lâu.
setInterval(()=>{
  const now = Date.now();
  for(const [key, rec] of failedAttempts.entries()){
    const staleWindow = !rec.lockedUntil && (now - rec.firstAt) > BRUTE_FORCE_WINDOW_MS;
    const staleLock = rec.lockedUntil && rec.lockedUntil < now - BRUTE_FORCE_WINDOW_MS;
    if(staleWindow || staleLock) failedAttempts.delete(key);
  }
}, 5 * 60 * 1000);

/* ---- Ghi log cảnh báo khi 1 IP gửi request với tốc độ bất thường (khả năng DoS/spam) ----
   CHỈ ghi log + trả 429 cho chính request đó, KHÔNG chặn IP ở tầng mạng, KHÔNG gửi gì
   ngược lại phía người gửi. Admin có thể xem log này trên console/server log để tự
   quyết định chặn ở tầng hạ tầng (firewall/CDN) nếu cần. */
const globalRequestLog = new Map(); // ip -> [timestamps]
const ABUSE_WARN_THRESHOLD = 120;   // số request/phút để coi là bất thường
function trackAndWarnAbuse(ip){
  const now = Date.now();
  let arr = globalRequestLog.get(ip);
  if(!arr){ arr = []; globalRequestLog.set(ip, arr); }
  while(arr.length && now - arr[0] > 60 * 1000) arr.shift();
  arr.push(now);
  if(arr.length === ABUSE_WARN_THRESHOLD){
    console.warn(`[Security] Cảnh báo: IP ${ip} đã gửi ${arr.length} request trong 60 giây gần nhất — có thể là spam/DoS. Vui lòng kiểm tra log và tự chặn ở tầng firewall/CDN nếu cần thiết.`);
  }
  return arr.length;
}
setInterval(()=>{
  const now = Date.now();
  for(const [ip, arr] of globalRequestLog.entries()){
    while(arr.length && now - arr[0] > 5 * 60 * 1000) arr.shift();
    if(arr.length === 0) globalRequestLog.delete(ip);
  }
}, 5 * 60 * 1000);

/* ---- Validate số tiền/số lượng dùng chung, chống bug do NaN/Infinity/số âm/số quá lớn ----
   Trả về number hợp lệ hoặc null nếu không hợp lệ — bên gọi PHẢI kiểm tra null và từ chối. */
function parseSafeAmount(raw, { min = 1, max = 1000000000 } = {}){
  const cleaned = String(raw == null ? '' : raw).replace(/[^\d.-]/g, '');
  const n = parseFloat(cleaned);
  if(!Number.isFinite(n)) return null;
  if(Number.isNaN(n)) return null;
  const rounded = Math.round(n); // tiền VNĐ luôn là số nguyên, tránh sai số dấu phẩy động
  if(rounded < min || rounded > max) return null;
  return rounded;
}

/* ---- Khoá đơn giản chống race-condition khi nhiều request cùng sửa 1 tài khoản ----
   (ví dụ 2 request mua key/nạp tiền gửi gần như đồng thời cho cùng 1 khách hàng).
   Vì Node.js xử lý tuần tự trên 1 luồng giữa các "await", nguy cơ chính là 2 request
   cùng đọc số dư CŨ trước khi request đầu ghi xong. Hàng đợi theo customerId đảm bảo
   các thao tác ghi số dư của CÙNG 1 khách hàng luôn chạy nối tiếp, không chồng lấp. */
const customerLocks = new Map(); // customerId -> Promise đang chạy (đuôi hàng đợi)
function withCustomerLock(customerId, fn){
  const prev = customerLocks.get(customerId) || Promise.resolve();
  const next = prev.then(fn, fn); // chạy fn() sau khi tác vụ trước xong, dù trước đó lỗi hay không
  // Lưu lại "đuôi" hàng đợi, nhưng luôn bắt lỗi để không làm vỡ map nếu fn() reject.
  customerLocks.set(customerId, next.catch(()=>{}));
  return next;
}

/* Chặn crash toàn cục để Render không báo "Exited with status 1" vì lỗi nhỏ không bắt được. */
process.on('uncaughtException', (err) => {
  console.error('[KeyVault] uncaughtException (đã chặn, server vẫn tiếp tục chạy):', err && err.stack ? err.stack : err);
});
process.on('unhandledRejection', (reason) => {
  console.error('[KeyVault] unhandledRejection (đã chặn, server vẫn tiếp tục chạy):', reason);
});

/* Giao diện dashboard quản trị (HTML/CSS/JS), nhúng thành chuỗi HTML_PAGE, phục vụ ở "/admin". */
const HTML_LINES = [
  "<!DOCTYPE html>",
  "<html lang=\"vi\">",
  "<head>",
  "<meta charset=\"UTF-8\">",
  "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">",
  "<title>KeyVault — Hệ thống tạo & quản lý Key</title>",
  "<link rel=\"preconnect\" href=\"https://fonts.googleapis.com\">",
  "<link href=\"https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@500;600;700&family=Inter:wght@400;500;600&family=JetBrains+Mono:wght@500;600;700&display=swap\" rel=\"stylesheet\">",
  "<style>",
  "  :root{",
  "    --ink:#F7F7F5;",
  "    --panel:#FFFFFF;",
  "    --panel-2:#FBFBF9;",
  "    --line:#E4E3DD;",
  "    --brass:#AD7F1E;",
  "    --brass-soft:#C99A2E;",
  "    --brass-tint:#F6ECD3;",
  "    --text:#1C1B18;",
  "    --muted:#7C7A72;",
  "    --ok:#1F8F63;",
  "    --ok-tint:#E4F5EE;",
  "    --danger:#C23B4B;",
  "    --danger-tint:#FBEAEC;",
  "    --warn:#B4791A;",
  "    --warn-tint:#FBF0DC;",
  "    --info:#2D6FBB;",
  "    --info-tint:#E7F0FB;",
  "    --shadow: 0 1px 2px rgba(28,27,24,0.04), 0 8px 24px -12px rgba(28,27,24,0.10);",
  "  }",
  "  *{box-sizing:border-box;}",
  "  html,body{margin:0;padding:0;}",
  "  body{",
  "    background:",
  "      radial-gradient(1000px 500px at 88% -8%, #FBF2DC 0%, transparent 60%),",
  "      var(--ink);",
  "    color:var(--text);",
  "    font-family:'Inter',sans-serif;",
  "    min-height:100vh;",
  "  }",
  "  ::selection{background:var(--brass-tint); color:var(--text);}",
  "  ::-webkit-scrollbar{width:10px; height:10px;}",
  "  ::-webkit-scrollbar-thumb{background:#DFDDD3; border-radius:20px;}",
  "  ::-webkit-scrollbar-track{background:transparent;}",
  "",
  "  /* ============ LOGIN SCREEN ============ */",
  "  #loginScreen{",
  "    min-height:100vh; display:flex; align-items:center; justify-content:center;",
  "    padding:24px;",
  "    background:",
  "      radial-gradient(900px 500px at 15% 0%, #FBF2DC 0%, transparent 55%),",
  "      radial-gradient(700px 500px at 100% 100%, #F3EFE4 0%, transparent 55%),",
  "      var(--ink);",
  "  }",
  "  .login-card{",
  "    width:100%; max-width:400px;",
  "    background:var(--panel);",
  "    border:1px solid var(--line);",
  "    border-radius:18px;",
  "    box-shadow:var(--shadow);",
  "    padding:38px 34px 32px;",
  "  }",
  "  .login-brand{display:flex; flex-direction:column; align-items:center; text-align:center; margin-bottom:26px;}",
  "  .login-brand .mark{",
  "    width:52px; height:52px; border-radius:14px; margin-bottom:14px;",
  "    background:linear-gradient(155deg, var(--brass-soft), var(--brass) 65%);",
  "    display:flex; align-items:center; justify-content:center;",
  "    box-shadow:0 8px 20px -8px #AD7F1E70;",
  "  }",
  "  .login-brand .mark svg{width:26px; height:26px;}",
  "  .login-brand h1{font-family:'Space Grotesk',sans-serif; font-size:22px; margin:0;}",
  "  .login-brand p{font-size:12.5px; color:var(--muted); margin:6px 0 0; letter-spacing:.2px;}",
  "",
  "  .login-field{margin-bottom:16px;}",
  "  .login-field label{display:block; font-size:12px; color:var(--muted); margin-bottom:6px; font-weight:500;}",
  "  .login-field input{",
  "    width:100%; background:var(--panel-2); border:1px solid var(--line); color:var(--text);",
  "    padding:12px 14px; border-radius:10px; font-family:'Inter',sans-serif; font-size:13.5px;",
  "    outline:none; transition:border-color .15s, box-shadow .15s;",
  "  }",
  "  .login-field input:focus{border-color:var(--brass-soft); box-shadow:0 0 0 3px #C99A2E1f;}",
  "",
  "  .login-row{display:flex; align-items:center; justify-content:space-between; margin:2px 0 20px;}",
  "  .login-remember{display:flex; align-items:center; gap:7px; font-size:12.5px; color:var(--muted);}",
  "  .login-remember input{accent-color:var(--brass);}",
  "  .login-forgot{font-size:12.5px; color:var(--brass); text-decoration:none; font-weight:600;}",
  "  .login-forgot:hover{text-decoration:underline;}",
  "",
  "  .login-error{",
  "    display:none; background:var(--danger-tint); color:var(--danger); border:1px solid #C23B4B30;",
  "    font-size:12.5px; padding:10px 12px; border-radius:9px; margin-bottom:16px; font-weight:500;",
  "  }",
  "  .login-error.show{display:block;}",
  "",
  "  .login-demo{",
  "    margin-top:20px; text-align:center; font-size:11.5px; color:var(--muted);",
  "    border-top:1px dashed var(--line); padding-top:16px; line-height:1.6;",
  "  }",
  "  .login-demo code{",
  "    background:var(--brass-tint); color:var(--brass); padding:2px 7px; border-radius:5px;",
  "    font-family:'JetBrains Mono',monospace; font-weight:600;",
  "  }",
  "",
  "  /* ============ APP SHELL ============ */",
  "  #appRoot{display:none;}",
  "",
  "  header.top{",
  "    padding:0 32px;",
  "    border-bottom:1px solid var(--line);",
  "    position:sticky; top:0; background:rgba(255,255,255,0.92); backdrop-filter:blur(10px); z-index:20;",
  "  }",
  "  .top-row{",
  "    display:flex; align-items:center; justify-content:space-between;",
  "    padding:20px 0 16px;",
  "  }",
  "  .brand{display:flex; align-items:center; gap:12px;}",
  "  .brand .mark{",
  "    width:34px; height:34px; border-radius:9px;",
  "    background:linear-gradient(155deg, var(--brass-soft), var(--brass) 65%);",
  "    display:flex; align-items:center; justify-content:center;",
  "    box-shadow:0 4px 14px -4px #AD7F1E60;",
  "  }",
  "  .brand .mark svg{width:18px; height:18px;}",
  "  .brand h1{font-family:'Space Grotesk',sans-serif; font-size:18px; margin:0; letter-spacing:0.2px; color:var(--text);}",
  "  .brand .tag{font-size:11px; color:var(--muted); letter-spacing:1.5px; text-transform:uppercase; margin-top:1px;}",
  "",
  "  .header-right{display:flex; align-items:center; gap:26px;}",
  "  .stats{display:flex; gap:22px; flex-wrap:wrap; justify-content:flex-end;}",
  "  .stat{text-align:right;}",
  "  .stat .n{font-family:'JetBrains Mono',monospace; font-size:18px; font-weight:700; color:var(--text);}",
  "  .stat .l{font-size:10px; color:var(--muted); text-transform:uppercase; letter-spacing:1px;}",
  "  .logout-btn{",
  "    display:flex; align-items:center; gap:7px;",
  "    background:var(--panel-2); border:1px solid var(--line); color:var(--muted);",
  "    padding:9px 14px; border-radius:9px; font-size:12.5px; font-weight:600; cursor:pointer;",
  "    transition:.15s; font-family:'Inter',sans-serif;",
  "  }",
  "  .logout-btn:hover{border-color:var(--danger); color:var(--danger);}",
  "  .logout-btn svg{width:14px; height:14px;}",
  "  .ghost-icon-btn{",
  "    display:flex; align-items:center; gap:7px;",
  "    background:var(--panel-2); border:1px solid var(--line); color:var(--muted);",
  "    padding:9px 12px; border-radius:9px; font-size:12.5px; font-weight:600; cursor:pointer;",
  "    transition:.15s; font-family:'Inter',sans-serif;",
  "  }",
  "  .ghost-icon-btn:hover{border-color:var(--brass-soft); color:var(--brass);}",
  "  .ghost-icon-btn.active{border-color:var(--brass-soft); color:var(--brass); background:var(--brass-tint);}",
  "  .ghost-icon-btn svg{width:14px; height:14px;}",
  "  .stat-balance{color:var(--ok); font-weight:600;}",
  "",
  "  .tabnav{display:flex; gap:6px; padding-bottom:0;}",
  "  .tab-btn{",
  "    background:transparent; border:none; color:var(--muted); font-weight:600; font-size:13px;",
  "    padding:11px 6px; cursor:pointer; position:relative; font-family:'Inter',sans-serif;",
  "    border-bottom:2px solid transparent; margin-right:14px; transition:.15s;",
  "  }",
  "  .tab-btn:hover{color:var(--text);}",
  "  .tab-btn.active{color:var(--brass); border-bottom-color:var(--brass);}",
  "",
  "  main{max-width:1280px; margin:0 auto; padding:32px;}",
  "  #page-keys{display:grid; grid-template-columns:340px 1fr; gap:28px;}",
  "  @media (max-width:920px){ #page-keys{grid-template-columns:1fr;} }",
  "",
  "  .panel{",
  "    background:var(--panel);",
  "    border:1px solid var(--line); border-radius:14px; padding:22px;",
  "    box-shadow:var(--shadow);",
  "  }",
  "  .panel h2{",
  "    font-family:'Space Grotesk',sans-serif; font-size:14px; margin:0 0 4px;",
  "    text-transform:uppercase; letter-spacing:1.2px; color:var(--brass);",
  "  }",
  "  .panel .sub{font-size:12px; color:var(--muted); margin:0 0 18px;}",
  "  .panel + .panel{margin-top:24px;}",
  "",
  "  label{display:block; font-size:12px; color:var(--muted); margin:14px 0 6px; font-weight:500;}",
  "  label:first-of-type{margin-top:0;}",
  "  input[type=text], input[type=number], select{",
  "    width:100%; background:var(--panel-2); border:1px solid var(--line); color:var(--text);",
  "    padding:10px 12px; border-radius:8px; font-family:'JetBrains Mono',monospace; font-size:13px;",
  "    outline:none; transition:border-color .15s, box-shadow .15s;",
  "  }",
  "  input[type=text]:focus, input[type=number]:focus, select:focus{border-color:var(--brass-soft); box-shadow:0 0 0 3px #C99A2E1f;}",
  "  .row2{display:grid; grid-template-columns:1fr 1fr; gap:10px;}",
  "  .row3{display:grid; grid-template-columns:1fr 1fr 1fr; gap:10px;}",
  "",
  "  .chip-toggle{display:flex; gap:8px; flex-wrap:wrap;}",
  "  .chip-toggle input{display:none;}",
  "  .chip-toggle label{",
  "    margin:0; display:inline-block; padding:7px 12px; border-radius:20px;",
  "    border:1px solid var(--line); font-size:11.5px; color:var(--muted); cursor:pointer;",
  "    user-select:none; transition:.15s; background:var(--panel-2);",
  "  }",
  "  .chip-toggle input:checked + label{",
  "    border-color:var(--brass-soft); color:var(--brass); background:var(--brass-tint);",
  "  }",
  "",
  "  .btn{",
  "    width:100%; margin-top:20px; padding:13px; border:none; border-radius:9px;",
  "    background:linear-gradient(155deg, var(--brass-soft), var(--brass));",
  "    color:#fff; font-weight:700; font-size:13.5px; letter-spacing:.3px;",
  "    cursor:pointer; transition:transform .1s, box-shadow .15s;",
  "    font-family:'Space Grotesk',sans-serif;",
  "  }",
  "  .btn:hover{box-shadow:0 8px 22px -8px #AD7F1E80; transform:translateY(-1px);}",
  "  .btn:active{transform:translateY(0);}",
  "  .btn:disabled{opacity:.55; cursor:not-allowed; transform:none; box-shadow:none;}",
  "  .btn-ghost{",
  "    background:var(--panel-2); border:1px solid var(--line); color:var(--muted); font-weight:600;",
  "  }",
  "  .btn-ghost:hover{border-color:var(--brass-soft); color:var(--brass); box-shadow:none;}",
  "  .btn-danger-ghost{background:var(--panel-2);border:1px solid #C23B4B40;color:var(--danger);font-weight:600;}",
  "  .btn-danger-ghost:hover{border-color:var(--danger); color:#fff; background:var(--danger);}",
  "  .btn-inline{width:auto; margin-top:0; padding:9px 16px; font-size:12.5px;}",
  "",
  "  .preview-note{",
  "    margin-top:16px; font-size:11.5px; color:var(--muted); line-height:1.5;",
  "    border-left:2px solid var(--line); padding-left:10px;",
  "  }",
  "  .preview-note code{color:var(--brass); font-family:'JetBrains Mono',monospace;}",
  "",
  "  /* Toolbar / filters */",
  "  .toolbar{display:flex; gap:10px; align-items:center; margin-bottom:18px; flex-wrap:wrap;}",
  "  .toolbar input[type=text]{flex:1; min-width:180px;}",
  "  .toolbar select{width:auto; min-width:130px;}",
  "  .toolbar .spacer{flex:1;}",
  "",
  "  /* Ticket / key card */",
  "  .roll{display:flex; flex-direction:column; gap:10px;}",
  "  .ticket{",
  "    position:relative;",
  "    background:var(--panel-2);",
  "    border:1px solid var(--line);",
  "    border-radius:10px;",
  "    padding:14px 18px;",
  "    display:flex; flex-direction:column; gap:10px;",
  "  }",
  "  .ticket::before, .ticket::after{",
  "    content:\"\"; position:absolute; width:14px; height:14px; background:var(--ink);",
  "    border:1px solid var(--line); border-radius:50%; top:50%; transform:translateY(-50%);",
  "  }",
  "  .ticket::before{left:-7px;}",
  "  .ticket::after{right:-7px;}",
  "  .ticket-top{display:flex; justify-content:space-between; align-items:flex-start; gap:12px;}",
  "  .ticket .key{",
  "    font-family:'JetBrains Mono',monospace; font-size:14.5px; font-weight:600;",
  "    letter-spacing:0.5px; word-break:break-all; color:var(--text);",
  "  }",
  "  .ticket-badges{display:flex; gap:6px; flex-shrink:0; flex-wrap:wrap; justify-content:flex-end;}",
  "  .ticket-bottom{display:flex; justify-content:space-between; align-items:center; gap:12px; flex-wrap:wrap;}",
  "  .ticket .meta{font-size:11px; color:var(--muted); line-height:1.7;}",
  "  .ticket .meta b{color:var(--text); font-weight:600;}",
  "  .ticket .meta .expired-txt{color:var(--danger); font-weight:600;}",
  "  .ticket .meta .active-txt{color:var(--ok); font-weight:600;}",
  "",
  "  .badge{",
  "    font-size:10.5px; padding:4px 10px; border-radius:20px; text-transform:uppercase;",
  "    letter-spacing:.5px; font-weight:600; white-space:nowrap;",
  "  }",
  "  .badge.available{background:var(--ok-tint); color:var(--ok); border:1px solid #1F8F6330;}",
  "  .badge.sold{background:var(--brass-tint); color:var(--brass); border:1px solid #AD7F1E30;}",
  "  .badge.banned{background:var(--danger-tint); color:var(--danger); border:1px solid #C23B4B30;}",
  "  .badge.expired{background:#EDECE7; color:var(--muted); border:1px solid var(--line);}",
  "  .badge.unactivated{background:var(--info-tint); color:var(--info); border:1px solid #2D6FBB30;}",
  "  .badge.normal{background:#EDECE7; color:var(--muted); border:1px solid var(--line);}",
  "  .badge.premium{background:var(--brass-tint); color:var(--brass); border:1px solid #AD7F1E30;}",
  "  .badge.active{background:var(--ok-tint); color:var(--ok); border:1px solid #1F8F6330;}",
  "",
  "  .actions{display:flex; gap:6px; flex-wrap:wrap;}",
  "  .icon-btn{",
  "    background:var(--panel); border:1px solid var(--line); color:var(--muted);",
  "    width:32px; height:32px; border-radius:7px; cursor:pointer;",
  "    display:flex; align-items:center; justify-content:center; transition:.15s; flex-shrink:0;",
  "  }",
  "  .icon-btn:hover{border-color:var(--brass-soft); color:var(--brass);}",
  "  .icon-btn.danger:hover{border-color:var(--danger); color:var(--danger);}",
  "  .icon-btn svg{width:15px; height:15px;}",
  "",
  "  .empty{",
  "    text-align:center; padding:60px 20px; color:var(--muted);",
  "    border:1px dashed var(--line); border-radius:12px;",
  "  }",
  "  .empty .big{font-family:'Space Grotesk',sans-serif; color:var(--text); font-size:16px; margin-bottom:6px;}",
  "",
  "  .toast{",
  "    position:fixed; bottom:24px; left:50%; transform:translateX(-50%) translateY(20px);",
  "    background:var(--text); border:1px solid var(--text); color:#fff;",
  "    padding:11px 20px; border-radius:9px; font-size:13px; font-weight:600;",
  "    opacity:0; pointer-events:none; transition:.25s; z-index:50;",
  "    font-family:'JetBrains Mono',monospace;",
  "    box-shadow:0 10px 30px -10px rgba(0,0,0,0.35);",
  "    max-width:80vw; text-align:center;",
  "  }",
  "  .toast.show{opacity:1; transform:translateX(-50%) translateY(0);}",
  "",
  "  .modal-bg{",
  "    position:fixed; inset:0; background:#1C1B1866; display:none;",
  "    align-items:center; justify-content:center; z-index:60; backdrop-filter:blur(3px);",
  "  }",
  "  .modal-bg.show{display:flex;}",
  "  .modal{",
  "    background:var(--panel); border:1px solid var(--line); border-radius:14px;",
  "    padding:26px; width:340px; box-shadow:var(--shadow);",
  "  }",
  "  .modal h3{margin:0 0 14px; font-family:'Space Grotesk',sans-serif; font-size:15px; color:var(--text);}",
  "  .modal .row2{margin-bottom:4px;}",
  "  .modal-actions{display:flex; gap:10px; margin-top:18px;}",
  "  .modal-actions .btn{margin-top:0;}",
  "",
  "  footer{text-align:center; padding:30px; color:var(--muted); font-size:11.5px;}",
  "",
  "  /* ============ STATS / SECURITY PAGES ============ */",
  "  .stats-grid{display:grid; grid-template-columns:repeat(auto-fit,minmax(180px,1fr)); gap:16px; margin-bottom:24px;}",
  "  .stat-card{background:var(--panel); border:1px solid var(--line); border-radius:14px; padding:18px 20px; box-shadow:var(--shadow);}",
  "  .stat-card .n{font-family:'JetBrains Mono',monospace; font-size:24px; font-weight:700; color:var(--text);}",
  "  .stat-card .l{font-size:11.5px; color:var(--muted); margin-top:4px;}",
  "  .stat-card .n.warn{color:var(--warn);}",
  "  .stat-card .n.danger{color:var(--danger);}",
  "  .stat-card .n.ok{color:var(--ok);}",
  "",
  "  table{width:100%; border-collapse:collapse; font-size:12.8px;}",
  "  th{text-align:left; color:var(--muted); font-weight:600; font-size:10.5px; text-transform:uppercase;",
  "     letter-spacing:.6px; padding:10px 12px; border-bottom:1px solid var(--line);}",
  "  td{padding:12px; border-bottom:1px solid var(--line); color:var(--text); vertical-align:middle;}",
  "  tr:last-child td{border-bottom:none;}",
  "  .table-wrap{overflow-x:auto;}",
  "  .mono{font-family:'JetBrains Mono',monospace;}",
  "",
  "  .barchart{display:flex; align-items:flex-end; gap:12px; height:150px; padding:12px 6px 0;}",
  "  .bar-col{flex:1; display:flex; flex-direction:column; align-items:center; justify-content:flex-end; gap:8px; height:100%;}",
  "  .bar{width:100%; max-width:38px; background:linear-gradient(180deg, var(--brass-soft), var(--brass)); border-radius:6px 6px 3px 3px; min-height:4px; transition:height .4s;}",
  "  .bar-label{font-size:10px; color:var(--muted); text-align:center;}",
  "  .bar-val{font-size:11px; font-weight:700; color:var(--text); font-family:'JetBrains Mono',monospace;}",
  "",
  "  .split-2{display:grid; grid-template-columns:1fr 1fr; gap:24px;}",
  "  @media (max-width:800px){ .split-2{grid-template-columns:1fr;} }",
  "",
  "  .type-bar-row{margin-bottom:14px;}",
  "  .type-bar-row .lbl{display:flex; justify-content:space-between; font-size:12px; margin-bottom:6px;}",
  "  .type-bar-track{background:var(--panel-2); border:1px solid var(--line); height:10px; border-radius:20px; overflow:hidden;}",
  "  .type-bar-fill{height:100%; border-radius:20px;}",
  "",
  "  .pill{font-size:10.5px; padding:4px 10px; border-radius:20px; font-weight:600; white-space:nowrap;}",
  "  .pill.ok{background:var(--ok-tint); color:var(--ok);}",
  "  .pill.danger{background:var(--danger-tint); color:var(--danger);}",
  "  .pill.warn{background:var(--warn-tint); color:var(--warn);}",
  "  .pill.info{background:var(--info-tint); color:var(--info);}",
  "",
  "  .progress-track{background:var(--panel-2); border:1px solid var(--line); border-radius:20px; height:10px; overflow:hidden; margin:18px 0 6px;}",
  "  .progress-fill{height:100%; width:0%; background:linear-gradient(90deg, var(--brass-soft), var(--brass)); transition:width .25s;}",
  "  .progress-label{font-size:11.5px; color:var(--muted); text-align:center;}",
  "",
  "  .scan-item{display:flex; justify-content:space-between; align-items:center; padding:12px 14px;",
  "    border:1px solid var(--line); border-radius:10px; margin-bottom:8px; background:var(--panel-2);}",
  "  .scan-item .name{font-size:13px; font-weight:600;}",
  "  .scan-item .desc{font-size:11.5px; color:var(--muted); margin-top:2px;}",
  "",
  "  .sec-note{",
  "    margin-top:6px; font-size:11.5px; color:var(--muted); line-height:1.6;",
  "    background:var(--info-tint); border:1px solid #2D6FBB30; padding:12px 14px; border-radius:10px;",
  "  }",
  "  .panel-head{display:flex; align-items:center; justify-content:space-between; gap:12px; flex-wrap:wrap; margin-bottom:4px;}",
  "",
  "  /* ============ PREMIUM SELLER / ACCOUNT UPGRADE ============ */",
  "  .vip-badge{",
  "    display:inline-flex; align-items:center; gap:4px; margin-left:8px;",
  "    background:linear-gradient(120deg,#7A4E00,#C99A2E 45%,#F3D67A 60%,#C99A2E 75%,#7A4E00);",
  "    background-size:220% auto; color:#fff; font-family:'Space Grotesk',sans-serif;",
  "    font-size:10px; font-weight:700; letter-spacing:.6px; padding:4px 10px; border-radius:20px;",
  "    box-shadow:0 4px 14px -4px #AD7F1E90; animation:shimmer 3.5s linear infinite;",
  "  }",
  "  @keyframes shimmer{ 0%{background-position:0% 50%;} 100%{background-position:220% 50%;} }",
  "  body.vip-mode header.top{",
  "    background:",
  "      linear-gradient(rgba(255,255,255,0.90),rgba(255,255,255,0.90)),",
  "      radial-gradient(1200px 220px at 10% 0%, #F6ECD3 0%, transparent 60%);",
  "    border-bottom:1px solid var(--brass-soft);",
  "  }",
  "  body.vip-mode .brand .mark{",
  "    box-shadow:0 0 0 3px #F6ECD3, 0 6px 18px -6px #AD7F1E90;",
  "  }",
  "  body.vip-mode .panel{ border-color:#E9D9AE; }",
  "",
  "  .badge.normal.acct{background:#EDECE7; color:var(--muted); border:1px solid var(--line);}",
  "  .badge.premium.acct{background:linear-gradient(120deg, var(--brass-tint), #FBF2DC); color:var(--brass); border:1px solid #AD7F1E40; font-weight:700;}",
  "",
  "  .chip-toggle input:disabled + label{",
  "    opacity:.45; cursor:not-allowed; text-decoration:line-through;",
  "  }",
  "",
  "  .notif-panel{border-color:#E9D9AE;}",
  "  .notif-item{",
  "    display:flex; align-items:flex-start; gap:10px; padding:12px 14px;",
  "    border:1px solid var(--line); border-radius:10px; margin-bottom:8px; background:var(--panel-2);",
  "  }",
  "  .notif-item.unread{border-color:var(--brass-soft); background:var(--brass-tint);}",
  "  .notif-item .dot{width:8px; height:8px; border-radius:50%; background:var(--brass); margin-top:5px; flex-shrink:0;}",
  "  .notif-item.unread .dot{background:var(--ok);}",
  "  .notif-item .body{flex:1;}",
  "  .notif-item .msg{font-size:12.8px; color:var(--text); line-height:1.5;}",
  "  .notif-item .time{font-size:10.5px; color:var(--muted); margin-top:3px;}",
  "",
  "  .price-table{width:100%; border-collapse:collapse; margin-top:10px; font-size:12px;}",
  "  .price-table td{padding:6px 8px; border-bottom:1px dashed var(--line);}",
  "  .price-table td:last-child{text-align:right; font-family:'JetBrains Mono',monospace; font-weight:600; color:var(--brass);}",
  "</style>",
  "</head>",
  "<body>",
  "",
  "<!-- ============ LOGIN SCREEN ============ -->",
  "<div id=\"loginScreen\">",
  "  <div class=\"login-card\">",
  "    <div class=\"login-brand\">",
  "      <div class=\"mark\">",
  "        <svg viewBox=\"0 0 24 24\" fill=\"none\"><path d=\"M7 12a5 5 0 1 1 4.9-6H21v4h-2v3h-3v-3h-2.1A5 5 0 0 1 7 12Z\" stroke=\"#fff\" stroke-width=\"1.6\" stroke-linejoin=\"round\"/><circle cx=\"7\" cy=\"12\" r=\"1.4\" fill=\"#fff\"/></svg>",
  "      </div>",
  "      <h1>KeyVault</h1>",
  "      <p>Đăng nhập để quản lý hệ thống key</p>",
  "    </div>",
  "",
  "    <div class=\"login-error\" id=\"loginError\">Sai tên đăng nhập hoặc mật khẩu. Vui lòng thử lại.</div>",
  "",
  "    <div class=\"login-field\">",
  "      <label>Tên đăng nhập</label>",
  "      <input type=\"text\" id=\"loginUser\" placeholder=\"Adminn\" autocomplete=\"username\">",
  "    </div>",
  "    <div class=\"login-field\">",
  "      <label>Mật khẩu</label>",
  "      <input type=\"text\" id=\"loginPass\" placeholder=\"••••••••\" autocomplete=\"current-password\">",
  "    </div>",
  "",
  "    <div class=\"login-row\" style=\"justify-content:flex-end;\">",
  "      <a href=\"#\" class=\"login-forgot\" onclick=\"showToastLogin('Vui lòng liên hệ quản trị viên để lấy lại mật khẩu.'); return false;\">Quên mật khẩu?</a>",
  "    </div>",
  "",
  "    <button class=\"btn\" id=\"btnLogin\">Đăng nhập</button>",
  "",
  "    <div class=\"login-demo\">",
  "      🔒 Hệ thống bảo mật — an toàn — chất lượng<br>",
  "      Toàn bộ dữ liệu đăng nhập và thông tin key được mã hoá, xác thực qua máy chủ và lưu trữ an toàn.<br>",
  "      Tài khoản đăng nhập thành công sẽ được <b>tự động ghi nhớ</b> trên trình duyệt này.",
  "    </div>",
  "  </div>",
  "</div>",
  "",
  "<!-- ============ APP ============ -->",
  "<div id=\"appRoot\">",
  "",
  "<header class=\"top\">",
  "  <div class=\"top-row\">",
  "    <div class=\"brand\">",
  "      <div class=\"mark\">",
  "        <svg viewBox=\"0 0 24 24\" fill=\"none\"><path d=\"M7 12a5 5 0 1 1 4.9-6H21v4h-2v3h-3v-3h-2.1A5 5 0 0 1 7 12Z\" stroke=\"#fff\" stroke-width=\"1.6\" stroke-linejoin=\"round\"/><circle cx=\"7\" cy=\"12\" r=\"1.4\" fill=\"#fff\"/></svg>",
  "      </div>",
  "      <div>",
  "        <h1>KeyVault <span class=\"vip-badge\" id=\"vipBadge\" style=\"display:none;\">★ PREMIUM</span></h1>",
  "        <div class=\"tag\">Hệ thống tạo &amp; quản lý key</div>",
  "      </div>",
  "    </div>",
  "    <div class=\"header-right\">",
  "      <div class=\"stats\">",
  "        <div class=\"stat\" id=\"statBalanceWrap\" style=\"display:none;\"><div class=\"n\" id=\"statBalance\">0₫</div><div class=\"l\">Số dư tài khoản</div></div>",
  "        <div class=\"stat\" id=\"statAcctExpiryWrap\" style=\"display:none;\"><div class=\"n\" id=\"statAcctExpiry\">—</div><div class=\"l\">Hạn tài khoản</div></div>",
  "        <div class=\"stat\"><div class=\"n\" id=\"statTotal\">0</div><div class=\"l\">Tổng key</div></div>",
  "        <div class=\"stat\"><div class=\"n\" id=\"statAvail\">0</div><div class=\"l\">Còn hàng</div></div>",
  "        <div class=\"stat stat-toggleable\"><div class=\"n\" id=\"statSold\">0</div><div class=\"l\">Đã bán</div></div>",
  "        <div class=\"stat stat-toggleable\"><div class=\"n\" id=\"statExpired\">0</div><div class=\"l\">Hết hạn</div></div>",
  "        <div class=\"stat stat-toggleable\"><div class=\"n\" id=\"statBanned\">0</div><div class=\"l\">Bị cấm</div></div>",
  "        <div class=\"stat stat-toggleable\"><div class=\"n\" id=\"statRevenue\">0₫</div><div class=\"l\">Doanh thu</div></div>",
  "      </div>",
  "      <button class=\"ghost-icon-btn\" id=\"btnToggleStats\" title=\"Ẩn/hiện: đã bán, hết hạn, bị cấm, doanh thu\">",
  "        <svg id=\"iconEyeOpen\" viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"1.8\"><path d=\"M1 12s4-7 11-7 11 7 11 7-4 7-11 7-11-7-11-7Z\"/><circle cx=\"12\" cy=\"12\" r=\"3\"/></svg>",
  "        <svg id=\"iconEyeClosed\" style=\"display:none;\" viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"1.8\"><path d=\"M17.94 17.94A10.94 10.94 0 0 1 12 20c-7 0-11-8-11-8a20.3 20.3 0 0 1 5.06-6.06M9.9 4.24A9.6 9.6 0 0 1 12 4c7 0 11 8 11 8a20.3 20.3 0 0 1-3.22 4.44M14.12 14.12a3 3 0 1 1-4.24-4.24\"/><path d=\"M1 1l22 22\"/></svg>",
  "        <span id=\"toggleStatsLabel\">Ẩn số liệu</span>",
  "      </button>",
  "      <button class=\"ghost-icon-btn\" id=\"btnChangeOwnPassword\" title=\"Đổi mật khẩu tài khoản đang đăng nhập\">",
  "        <svg viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"1.8\"><rect x=\"5\" y=\"11\" width=\"14\" height=\"9\" rx=\"2\"/><path d=\"M8 11V7a4 4 0 0 1 8 0v4\"/></svg>",
  "        Đổi mật khẩu",
  "      </button>",
  "      <button class=\"logout-btn\" id=\"btnLogout\">",
  "        <svg viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"1.8\"><path d=\"M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4\"/><path d=\"M16 17l5-5-5-5\"/><path d=\"M21 12H9\"/></svg>",
  "        Đăng xuất",
  "      </button>",
  "    </div>",
  "  </div>",
  "  <nav class=\"tabnav\">",
  "    <button class=\"tab-btn active\" data-page=\"keys\">Quản lý Key</button>",
  "    <button class=\"tab-btn\" data-page=\"stats\">Thống kê</button>",
  "    <button class=\"tab-btn\" data-page=\"security\">Bảo mật Server</button>",
  "    <button class=\"tab-btn\" data-page=\"sellers\" data-admin-only=\"1\">Người bán</button>",
  "    <button class=\"tab-btn\" data-page=\"customers\" data-admin-only=\"1\">Người dùng</button>",
  "    <button class=\"tab-btn\" data-page=\"apikey\" data-admin-only=\"1\">API Key Server</button>",
  "    <button class=\"tab-btn\" data-page=\"products\" data-admin-only=\"1\">Sản phẩm &amp; Mã giảm giá</button>",
  "    <button class=\"tab-btn\" data-page=\"getkey\" data-admin-only=\"1\">GetKey</button>",
  "  </nav>",
  "</header>",
  "",
  "<main>",
  "",
  "  <!-- ============ THÔNG BÁO NHẬN TIỀN / CẬP NHẬT TÀI KHOẢN (CHỈ NGƯỜI BÁN) ============ -->",
  "  <div class=\"panel notif-panel\" id=\"sellerNotifPanel\" style=\"display:none; margin-bottom:24px;\">",
  "    <div class=\"panel-head\">",
  "      <div>",
  "        <h2>Thông báo tài khoản</h2>",
  "        <p class=\"sub\" style=\"margin:0;\">Thông báo nhận tiền, gia hạn và nâng cấp tài khoản từ quản trị viên.</p>",
  "      </div>",
  "      <button class=\"btn-ghost icon-btn\" style=\"width:auto; padding:0 14px; height:32px;\" id=\"btnMarkAllRead\">Đánh dấu đã đọc</button>",
  "    </div>",
  "    <div id=\"notifList\" style=\"margin-top:14px;\"></div>",
  "  </div>",
  "",
  "  <!-- ============ PAGE 1: QUẢN LÝ KEY ============ -->",
  "  <div id=\"page-keys\">",
  "    <!-- Generator panel -->",
  "    <div>",
  "      <div class=\"panel\">",
  "        <h2>Tạo key mới</h2>",
  "        <p class=\"sub\">Cấu hình định dạng, loại key và thời hạn sử dụng.</p>",
  "",
  "        <label>Tiền tố (prefix)</label>",
  "        <input type=\"text\" id=\"cfgPrefix\" placeholder=\"VD: PRO\" maxlength=\"10\" value=\"PRO\">",
  "",
  "        <div class=\"row2\">",
  "          <div>",
  "            <label>Số nhóm ký tự</label>",
  "            <input type=\"number\" id=\"cfgGroups\" value=\"4\" min=\"1\" max=\"8\">",
  "          </div>",
  "          <div>",
  "            <label>Độ dài mỗi nhóm</label>",
  "            <input type=\"number\" id=\"cfgLen\" value=\"4\" min=\"2\" max=\"10\">",
  "          </div>",
  "        </div>",
  "",
  "        <label>Bộ ký tự</label>",
  "        <div class=\"chip-toggle\" id=\"charsetToggle\">",
  "          <input type=\"radio\" name=\"cs\" id=\"csFull\" checked><label for=\"csFull\">A-Z 0-9</label>",
  "          <input type=\"radio\" name=\"cs\" id=\"csNoAmbig\"><label for=\"csNoAmbig\">Rõ ràng (bỏ 0/O, 1/I)</label>",
  "          <input type=\"radio\" name=\"cs\" id=\"csNum\"><label for=\"csNum\">Chỉ số</label>",
  "        </div>",
  "",
  "        <label>Loại key</label>",
  "        <div class=\"chip-toggle\">",
  "          <input type=\"radio\" name=\"ktype\" id=\"ktNormal\" value=\"normal\" checked><label for=\"ktNormal\">Thường</label>",
  "          <input type=\"radio\" name=\"ktype\" id=\"ktPremium\" value=\"premium\"><label for=\"ktPremium\">★ Premium</label>",
  "        </div>",
  "",
  "        <label>Thời hạn sử dụng</label>",
  "        <div class=\"chip-toggle\" id=\"expiryToggle\">",
  "          <input type=\"radio\" name=\"expiry\" id=\"expNone\" value=\"none\"><label for=\"expNone\">Không giới hạn</label>",
  "          <input type=\"radio\" name=\"expiry\" id=\"expLimited\" value=\"limited\" checked><label for=\"expLimited\">Có thời hạn</label>",
  "        </div>",
  "        <div id=\"expiryFields\" style=\"margin-top:10px;\">",
  "          <label>Chọn gói thời hạn (cố định, không thể chỉnh sửa số ngày/giờ)</label>",
  "          <select id=\"cfgFixedPlan\" style=\"width:100%;\">",
  "            <option value=\"h12\">12 giờ — 20.000₫</option>",
  "            <option value=\"d1\" selected>1 ngày — 30.000₫</option>",
  "            <option value=\"w1\">1 tuần — 60.000₫</option>",
  "            <option value=\"d15\">15 ngày — 90.000₫</option>",
  "            <option value=\"m1\">1 tháng — 160.000₫</option>",
  "          </select>",
  "        </div>",
  "        <p class=\"preview-note\" id=\"expiryLockNote\" style=\"display:none; color:var(--warn); border-left-color:var(--warn);\">",
  "          🔒 Tài khoản <b>Thường</b> chỉ được tạo key có thời hạn. Liên hệ quản trị viên để nâng cấp lên <b>Premium</b> và mở khoá tạo key không giới hạn.",
  "        </p>",
  "",
  "        <div id=\"sellerPriceNote\" style=\"display:none;\">",
  "          <label>Bảng giá tạo key (cố định, trừ vào số dư)</label>",
  "          <table class=\"price-table\">",
  "            <tr><td>Key 12 giờ</td><td>20.000₫</td></tr>",
  "            <tr><td>Key 1 ngày</td><td>30.000₫</td></tr>",
  "            <tr><td>Key 1 tuần</td><td>60.000₫</td></tr>",
  "            <tr><td>Key 15 ngày</td><td>90.000₫</td></tr>",
  "            <tr><td>Key 1 tháng</td><td>160.000₫</td></tr>",
  "            <tr><td>Key không giới hạn (Premium)</td><td>500.000₫</td></tr>",
  "          </table>",
  "          <p class=\"preview-note\" style=\"margin-top:8px;\">",
  "            Bảng giá và các mốc thời hạn ở trên là <b>cố định</b>, không thể chỉnh sửa trên giao diện (kể cả tài khoản Premium hay Thường).",
  "          </p>",
  "        </div>",
  "",
  "        <label>Số lượng key sinh</label>",
  "        <input type=\"number\" id=\"cfgQty\" value=\"10\" min=\"1\" max=\"500\">",
  "",
  "        <label>Số thiết bị cho phép / key</label>",
  "        <input type=\"number\" id=\"cfgMaxDevices\" value=\"1\" min=\"1\" max=\"20\">",
  "        <p class=\"preview-note\" style=\"margin-top:6px;\">Mỗi key chỉ được kích hoạt tối đa số thiết bị này. Mặc định <b>1</b> (1 key = 1 thiết bị). Có thể tăng lên nếu muốn cho phép dùng nhiều máy.</p>",
  "",
  "        <label>Giá bán mỗi key (tuỳ chọn)</label>",
  "        <input type=\"text\" id=\"cfgPrice\" placeholder=\"VD: 99000\">",
  "",
  "        <div id=\"createdAtAdminBlock\" data-admin-only=\"1\">",
  "          <label>Ngày giờ tạo key</label>",
  "          <div class=\"chip-toggle\" id=\"createdAtToggle\">",
  "            <input type=\"radio\" name=\"createdAtMode\" id=\"createdAtNow\" value=\"now\" checked><label for=\"createdAtNow\">Hiện tại</label>",
  "            <input type=\"radio\" name=\"createdAtMode\" id=\"createdAtCustom\" value=\"custom\"><label for=\"createdAtCustom\">Tuỳ chỉnh</label>",
  "          </div>",
  "          <div class=\"row2\" id=\"createdAtCustomField\" style=\"display:none; margin-top:10px;\">",
  "            <div style=\"grid-column:1/-1;\">",
  "              <label>Chọn giờ · ngày · tháng</label>",
  "              <input type=\"datetime-local\" id=\"cfgCreatedAt\">",
  "            </div>",
  "          </div>",
  "          <p class=\"preview-note\" style=\"margin-top:10px;\">",
  "            Chỉ tài khoản admin mới có thể tuỳ chỉnh ngày giờ tạo key (dùng để nhập lại key cũ, key đã bán trước đó...). Nếu chọn \"Có thời hạn\" ở trên, hạn dùng sẽ được tính dựa trên mốc thời gian này.",
  "          </p>",
  "        </div>",
  "",
  "        <div class=\"preview-note\">",
  "          Định dạng xem trước: <code id=\"formatPreview\">PRO-XXXX-XXXX-XXXX-XXXX</code>",
  "        </div>",
  "",
  "        <button class=\"btn\" id=\"btnGenerate\">Sinh key ngay</button>",
  "        <button class=\"btn btn-ghost\" style=\"margin-top:10px\" id=\"btnExport\">Xuất CSV toàn bộ</button>",
  "        <button class=\"btn btn-ghost\" style=\"margin-top:10px\" id=\"btnOpenExtendAll\" data-admin-only=\"1\">⏱ Gia hạn tất cả key</button>",
  "        <button class=\"btn btn-danger-ghost\" style=\"margin-top:10px\" id=\"btnClear\">Xoá toàn bộ key</button>",
  "",
  "        <p class=\"preview-note\" style=\"margin-top:18px;\">",
  "          Lưu ý: dữ liệu key được lưu trong bộ nhớ phiên làm việc của trình duyệt (không lưu máy chủ). Tải lại trang sẽ mất dữ liệu — hãy xuất CSV để lưu trữ lâu dài.",
  "        </p>",
  "      </div>",
  "    </div>",
  "",
  "    <!-- List panel -->",
  "    <div class=\"panel\">",
  "      <h2>Danh sách key</h2>",
  "      <p class=\"sub\">Quản lý trạng thái, đánh dấu đã bán, cấm/bỏ cấm, reset key hoặc reset thiết bị.</p>",
  "",
  "      <div class=\"toolbar\">",
  "        <input type=\"text\" id=\"search\" placeholder=\"Tìm theo key hoặc ghi chú khách hàng...\">",
  "        <select id=\"filterStatus\">",
  "          <option value=\"all\">Tất cả trạng thái</option>",
  "          <option value=\"available\">Còn hàng</option>",
  "          <option value=\"sold\">Đã bán</option>",
  "          <option value=\"banned\">Bị cấm</option>",
  "          <option value=\"expired\">Hết hạn</option>",
  "          <option value=\"unactivated\">Chưa kích hoạt</option>",
  "        </select>",
  "        <select id=\"filterType\">",
  "          <option value=\"all\">Tất cả loại</option>",
  "          <option value=\"normal\">Thường</option>",
  "          <option value=\"premium\">Premium</option>",
  "        </select>",
  "        <div class=\"spacer\"></div>",
  "        <button class=\"btn-ghost icon-btn\" style=\"width:auto; padding:0 14px; height:36px;\" id=\"btnCopyAvail\">Copy key còn hàng</button>",
  "      </div>",
  "",
  "      <div class=\"roll\" id=\"rollList\"></div>",
  "      <div class=\"empty\" id=\"emptyState\">",
  "        <div class=\"big\">Chưa có key nào</div>",
  "        Sinh key mới ở bảng điều khiển bên trái để bắt đầu.",
  "      </div>",
  "    </div>",
  "  </div>",
  "",
  "  <!-- ============ PAGE 2: THỐNG KÊ ============ -->",
  "  <div id=\"page-stats\" style=\"display:none;\">",
  "    <div class=\"stats-grid\">",
  "      <div class=\"stat-card\"><div class=\"n\" id=\"stTotalKeys\">0</div><div class=\"l\">Tổng key đã tạo</div></div>",
  "      <div class=\"stat-card\"><div class=\"n ok\" id=\"stActiveKeys\">0</div><div class=\"l\">Key còn hiệu lực</div></div>",
  "      <div class=\"stat-card\"><div class=\"n danger\" id=\"stExpiredKeys\">0</div><div class=\"l\">Key đã hết hạn</div></div>",
  "      <div class=\"stat-card\"><div class=\"n\" id=\"stPremiumKeys\">0</div><div class=\"l\">Key Premium</div></div>",
  "      <div class=\"stat-card\"><div class=\"n\" id=\"stLoginCount\">0</div><div class=\"l\">Lượt đăng nhập</div></div>",
  "    </div>",
  "",
  "    <div class=\"split-2\">",
  "      <div class=\"panel\">",
  "        <h2>Key tạo theo 7 ngày gần nhất</h2>",
  "        <p class=\"sub\">Số lượng key được sinh ra mỗi ngày.</p>",
  "        <div class=\"barchart\" id=\"creationChart\"></div>",
  "      </div>",
  "      <div class=\"panel\">",
  "        <h2>Tỉ lệ loại key</h2>",
  "        <p class=\"sub\">Phân bổ giữa key Thường và Premium.</p>",
  "        <div id=\"typeBreakdown\"></div>",
  "      </div>",
  "    </div>",
  "",
  "    <div class=\"panel\" style=\"margin-top:24px;\">",
  "      <div class=\"panel-head\">",
  "        <div>",
  "          <h2>Hạn sử dụng key</h2>",
  "          <p class=\"sub\">Trạng thái còn hạn / hết hạn và thời gian còn lại của từng key.</p>",
  "        </div>",
  "      </div>",
  "      <div class=\"table-wrap\">",
  "        <table id=\"expiryTable\">",
  "          <thead><tr><th>Key</th><th>Loại</th><th>Trạng thái</th><th>Hết hạn lúc</th><th>Thời gian còn lại</th></tr></thead>",
  "          <tbody></tbody>",
  "        </table>",
  "      </div>",
  "    </div>",
  "",
  "    <div class=\"panel\" style=\"margin-top:24px;\">",
  "      <h2>Lịch sử đăng nhập</h2>",
  "      <p class=\"sub\">Ghi lại các lần đăng nhập vào hệ thống trong phiên này.</p>",
  "      <div class=\"table-wrap\">",
  "        <table id=\"loginTable\">",
  "          <thead><tr><th>Thời gian</th><th>Tài khoản</th><th>Kết quả</th></tr></thead>",
  "          <tbody></tbody>",
  "        </table>",
  "      </div>",
  "    </div>",
  "  </div>",
  "",
  "  <!-- ============ PAGE 3: BẢO MẬT SERVER ============ -->",
  "  <div id=\"page-security\" style=\"display:none;\">",
  "    <div class=\"sec-note\">",
  "      Đây là bảng điều khiển <b>mô phỏng</b> để minh hoạ giao diện. Vì đây là trang tĩnh chạy trong trình duyệt, không có máy chủ thật phía sau, nên số liệu chặn IP, DDoS và kết quả quét lỗ hổng bên dưới là dữ liệu giả lập, không phản ánh một hệ thống đang thực sự vận hành.",
  "    </div>",
  "",
  "    <div class=\"stats-grid\" style=\"margin-top:20px;\">",
  "      <div class=\"stat-card\"><div class=\"n danger\" id=\"secBlockedIP\">0</div><div class=\"l\">IP đang bị chặn</div></div>",
  "      <div class=\"stat-card\"><div class=\"n ok\" id=\"secStatus\">Chưa đánh giá</div><div class=\"l\">Trạng thái hệ thống</div></div>",
  "      <div class=\"stat-card\"><div class=\"n\" id=\"secLastScan\">Chưa đánh giá</div><div class=\"l\">Lần đánh giá gần nhất</div></div>",
  "    </div>",
  "",
  "    <div class=\"panel\">",
  "      <div class=\"panel-head\">",
  "        <div>",
  "          <h2>IP đã bị chặn</h2>",
  "          <p class=\"sub\">Danh sách IP do quản trị viên tự thêm/gỡ. Không có dữ liệu tự sinh.</p>",
  "        </div>",
  "        <button class=\"btn btn-ghost btn-inline\" id=\"btnRefreshIP\">+ Chặn IP mới</button>",
  "      </div>",
  "      <div class=\"table-wrap\">",
  "        <table id=\"ipTable\">",
  "          <thead><tr><th>Địa chỉ IP</th><th>Lý do</th><th>Thời gian</th><th>Trạng thái</th><th></th></tr></thead>",
  "          <tbody></tbody>",
  "        </table>",
  "      </div>",
  "    </div>",
  "",
  "    <div class=\"panel\" style=\"margin-top:24px;\">",
  "      <div class=\"panel-head\">",
  "        <div>",
  "          <h2>Checklist bảo mật (tự động)</h2>",
  "          <p class=\"sub\">Bấm \"Quét ngay\" để server tự kiểm tra thật các mục dưới đây (mật khẩu mặc định, HTTPS, rate-limit, phiên bản Node, IP đã chặn...). Không phải giả lập — kết quả lấy từ chính trạng thái server đang chạy.</p>",
  "        </div>",
  "        <button class=\"btn btn-inline\" id=\"btnAutoScan\" style=\"margin-top:0;\">🔄 Quét ngay</button>",
  "      </div>",
  "      <div id=\"autoScanResults\" style=\"margin-top:16px;\"></div>",
  "      <p class=\"preview-note\" style=\"margin-top:14px;\" id=\"autoScanSummary\">Chưa quét lần nào — bấm \"Quét ngay\" để bắt đầu.</p>",
  "    </div>",
  "  </div>",
  "",
  "  <!-- ============ PAGE 4: NGƯỜI BÁN (ADMIN ONLY) ============ -->",
  "  <div id=\"page-sellers\" style=\"display:none;\">",
  "    <div class=\"panel\">",
  "      <h2>Tạo tài khoản người bán</h2>",
  "      <p class=\"sub\">Tạo tài khoản đại lý/người bán. Mỗi tài khoản có kho key riêng và chỉ nhìn thấy đúng một trang \"Tạo key\" khi đăng nhập.</p>",
  "",
  "      <div class=\"row2\">",
  "        <div>",
  "          <label>Tên đăng nhập</label>",
  "          <input type=\"text\" id=\"sellerUsername\" placeholder=\"VD: dealer01\">",
  "        </div>",
  "        <div>",
  "          <label>Mật khẩu</label>",
  "          <input type=\"text\" id=\"sellerPassword\" placeholder=\"Mật khẩu đăng nhập\">",
  "        </div>",
  "      </div>",
  "",
  "      <label>Thời hạn tài khoản</label>",
  "      <div class=\"chip-toggle\" id=\"sellerExpiryToggle\">",
  "        <input type=\"radio\" name=\"sellerExpiry\" id=\"sellerExpNone\" value=\"none\" checked><label for=\"sellerExpNone\">Không giới hạn</label>",
  "        <input type=\"radio\" name=\"sellerExpiry\" id=\"sellerExpLimited\" value=\"limited\"><label for=\"sellerExpLimited\">Có thời hạn</label>",
  "      </div>",
  "      <div class=\"row2\" id=\"sellerExpiryFields\" style=\"display:none; margin-top:10px;\">",
  "        <div>",
  "          <label>Số lượng</label>",
  "          <input type=\"number\" id=\"sellerExpiryAmount\" value=\"30\" min=\"1\">",
  "        </div>",
  "        <div>",
  "          <label>Đơn vị</label>",
  "          <select id=\"sellerExpiryUnit\">",
  "            <option value=\"hour\">Giờ</option>",
  "            <option value=\"day\" selected>Ngày</option>",
  "            <option value=\"month\">Tháng</option>",
  "          </select>",
  "        </div>",
  "      </div>",
  "",
  "      <label>Số dư khởi tạo (tuỳ chọn, ₫)</label>",
  "      <input type=\"text\" id=\"sellerInitialBalance\" placeholder=\"VD: 0\">",
  "",
  "      <label>Loại tài khoản</label>",
  "      <div class=\"chip-toggle\" id=\"sellerAcctTypeToggle\">",
  "        <input type=\"radio\" name=\"sellerAcctType\" id=\"sellerAcctNormal\" value=\"normal\" checked><label for=\"sellerAcctNormal\">Thường</label>",
  "        <input type=\"radio\" name=\"sellerAcctType\" id=\"sellerAcctPremium\" value=\"premium\"><label for=\"sellerAcctPremium\">★ Premium</label>",
  "      </div>",
  "      <p class=\"preview-note\">",
  "        Tài khoản <b>Premium</b> được mở khoá tạo key <b>không giới hạn</b> thời gian và có hiệu ứng trang chủ VIP. Tài khoản <b>Thường</b> chỉ được tạo key có thời hạn. Có thể nâng/hạ cấp bất kỳ lúc nào ở bảng danh sách bên dưới.",
  "      </p>",
  "",
  "      <button class=\"btn\" id=\"btnCreateSeller\" style=\"margin-top:16px;\">Tạo tài khoản</button>",
  "    </div>",
  "",
  "    <div class=\"panel\" style=\"margin-top:24px;\">",
  "      <div class=\"panel-head\">",
  "        <div>",
  "          <h2>Danh sách tài khoản người bán</h2>",
  "          <p class=\"sub\">Quản lý hạn dùng, số dư, mật khẩu, cấm/bỏ cấm, gia hạn hoặc xoá tài khoản.</p>",
  "        </div>",
  "      </div>",
  "      <div class=\"table-wrap\">",
  "        <table id=\"sellerTable\">",
  "          <thead><tr><th>Tên đăng nhập</th><th>Ngày tạo</th><th>Hết hạn lúc</th><th>Còn lại</th><th>Trạng thái</th><th>Loại</th><th>Số dư</th><th>Số key đã tạo</th><th>Hành động</th></tr></thead>",
  "          <tbody></tbody>",
  "        </table>",
  "      </div>",
  "      <div class=\"empty\" id=\"sellerEmptyState\">",
  "        <div class=\"big\">Chưa có tài khoản người bán nào</div>",
  "        Tạo tài khoản ở bảng phía trên để bắt đầu.",
  "      </div>",
  "    </div>",
  "  </div>",
  "",
  "  <!-- ============ PAGE: NGƯỜI DÙNG (TÀI KHOẢN ĐĂNG KÝ Ở TRANG BÁN HÀNG) — ADMIN ONLY ============ -->",
  "  <div id=\"page-customers\" style=\"display:none;\">",
  "    <div class=\"panel\">",
  "      <div class=\"panel-head\">",
  "        <div>",
  "          <h2>Người dùng đã đăng ký</h2>",
  "          <p class=\"sub\">Tài khoản khách hàng đăng ký ở trang bán hàng (và tài khoản quản trị viên phụ). Thêm tiền, đổi mật khẩu cho từng tài khoản.</p>",
  "        </div>",
  "        <button class=\"btn-ghost icon-btn\" style=\"width:auto; padding:0 14px; height:36px;\" id=\"btnRefreshCustomers\">Làm mới</button>",
  "      </div>",
  "      <div class=\"table-wrap\">",
  "        <table id=\"customerTable\">",
  "          <thead><tr><th>Tên đăng nhập</th><th>Vai trò</th><th>Ngày tạo</th><th>IP lúc tạo</th><th>Số dư</th><th>Lượt nạp</th><th>Giao dịch</th><th>Hành động</th></tr></thead>",
  "          <tbody></tbody>",
  "        </table>",
  "      </div>",
  "      <div class=\"empty\" id=\"customerEmptyState\">",
  "        <div class=\"big\">Chưa có tài khoản người dùng nào</div>",
  "        Khách hàng đăng ký ở trang bán hàng sẽ tự động hiện ở đây.",
  "      </div>",
  "    </div>",
  "",
  "    <div class=\"panel\" style=\"margin-top:24px;\">",
  "      <div class=\"panel-head\">",
  "        <div>",
  "          <h2>Yêu cầu nạp tiền đang chờ duyệt</h2>",
  "          <p class=\"sub\">Khách hàng gửi yêu cầu nạp tiền (chuyển khoản) từ trang bán hàng — duyệt để cộng tiền vào tài khoản của họ.</p>",
  "        </div>",
  "      </div>",
  "      <div class=\"table-wrap\">",
  "        <table id=\"topupRequestTable\">",
  "          <thead><tr><th>Tên đăng nhập</th><th>Số tiền</th><th>Phương thức</th><th>Thời gian</th><th>Trạng thái</th><th>Hành động</th></tr></thead>",
  "          <tbody></tbody>",
  "        </table>",
  "      </div>",
  "      <div class=\"empty\" id=\"topupRequestEmptyState\">",
  "        <div class=\"big\">Không có yêu cầu nạp tiền nào đang chờ</div>",
  "      </div>",
  "    </div>",
  "",
  "    <div class=\"panel\" style=\"margin-top:24px;\">",
  "      <div class=\"panel-head\">",
  "        <div>",
  "          <h2>Cấu hình nhận tiền tự động (SePay)</h2>",
  "          <p class=\"sub\">Khi bật và cấu hình đúng, hệ thống sẽ tự động cộng tiền ngay khi khách chuyển khoản thành công, không cần duyệt tay. Xem hướng dẫn liên kết tại <a href=\\\"https://my.sepay.vn\\\" target=\\\"_blank\\\" rel=\\\"noopener\\\">my.sepay.vn</a>.</p>",
  "        </div>",
  "      </div>",
  "      <div style=\"display:grid; gap:14px; max-width:480px;\">",
  "        <div>",
  "          <label style=\"display:flex; align-items:center; gap:8px; cursor:pointer;\">",
  "            <input type=\"checkbox\" id=\"sepayEnabledToggle\" style=\"width:16px;height:16px;\">",
  "            <span>Bật đối soát tự động qua SePay</span>",
  "          </label>",
  "        </div>",
  "        <div>",
  "          <label>Ngân hàng nhận tiền</label>",
  "          <input type=\"text\" id=\"bankIdInput\" placeholder=\"VD: MB\">",
  "        </div>",
  "        <div>",
  "          <label>Số tài khoản</label>",
  "          <input type=\"text\" id=\"bankAccountNoInput\" placeholder=\"VD: 0364837118\">",
  "        </div>",
  "        <div>",
  "          <label>Tên chủ tài khoản</label>",
  "          <input type=\"text\" id=\"bankAccountNameInput\" placeholder=\"VD: LUONG VAN TUYEN\">",
  "        </div>",
  "        <div>",
  "          <label>API Key webhook SePay</label>",
  "          <input type=\"text\" id=\"sepayApiKeyInput\" placeholder=\"Dán API Key đã tạo trong SePay ở đây\">",
  "          <p class=\"sub\" style=\"margin-top:6px;\">Vào SePay &rarr; Webhooks &rarr; Tạo webhook mới, trỏ URL về <code id=\\\"sepayWebhookUrlHint\\\">(địa chỉ domain của bạn)/api/sepay-webhook</code>, chọn xác thực <b>API Key</b>, dán cùng giá trị vào cả 2 nơi.</p>",
  "        </div>",
  "        <div id=\"sepayConfigError\" style=\"display:none; color:#c0392b; font-size:13px;\"></div>",
  "        <div id=\"sepayConfigSuccess\" style=\"display:none; color:#1a7f37; font-size:13px;\"></div>",
  "        <div>",
  "          <button class=\"btn\" id=\"btnSaveSepayConfig\">Lưu cấu hình</button>",
  "        </div>",
  "      </div>",
  "    </div>",
  "  </div>",
  "",
  "  <!-- ============ PAGE 5: API KEY SERVER (ADMIN ONLY) ============ -->",
  "  <div id=\"page-apikey\" style=\"display:none;\">",
  "    <div class=\"sec-note\" id=\"apiConnStatusNote\">",
  "      Đang kiểm tra kết nối tới máy chủ backend…",
  "    </div>",
  "",
  "    <div class=\"stats-grid\" style=\"margin-top:20px;\">",
  "      <div class=\"stat-card\"><div class=\"n\" id=\"apiTotalApps\">0</div><div class=\"l\">Ứng dụng đã kết nối</div></div>",
  "      <div class=\"stat-card\"><div class=\"n warn\" id=\"apiPendingApps\">0</div><div class=\"l\">Đang chờ duyệt</div></div>",
  "      <div class=\"stat-card\"><div class=\"n ok\" id=\"apiAllowedApps\">0</div><div class=\"l\">Được phép dùng server</div></div>",
  "      <div class=\"stat-card\"><div class=\"n danger\" id=\"apiDeniedApps\">0</div><div class=\"l\">Bị từ chối</div></div>",
  "    </div>",
  "",
  "    <div class=\"panel\" style=\"margin-top:24px;\">",
  "      <h2>Link xác thực API Key</h2>",
  "      <p class=\"sub\">Dán link này vào code xác thực key trong app/tool của bạn để kiểm tra key có hợp lệ và app/tool của bạn có đang được phép dùng hệ thống này làm server key hay không.</p>",
  "",
  "      <label>Link xác thực (endpoint gốc)</label>",
  "      <div style=\"display:flex; gap:8px;\">",
  "        <input type=\"text\" id=\"apiVerifyLink\" readonly style=\"flex:1;\">",
  "        <button class=\"btn btn-ghost btn-inline\" id=\"btnCopyVerifyLink\">Sao chép</button>",
  "      </div>",
  "",
  "      <label>Link mẫu để kiểm tra một key cụ thể</label>",
  "      <div style=\"display:flex; gap:8px;\">",
  "        <input type=\"text\" id=\"apiVerifyExample\" readonly style=\"flex:1;\">",
  "        <button class=\"btn btn-ghost btn-inline\" id=\"btnCopyVerifyExample\">Sao chép</button>",
  "      </div>",
  "",
  "      <label>ID ứng dụng / tool của bạn (app_id) — tự đặt tên để hệ thống nhận diện</label>",
  "      <div style=\"display:flex; gap:8px;\">",
  "        <input type=\"text\" id=\"apiAppIdInput\" placeholder=\"VD: my-app-01\" value=\"my-app-01\" style=\"flex:1;\">",
  "        <button class=\"btn btn-ghost btn-inline\" id=\"btnGenAppExample\">Tạo lại link mẫu</button>",
  "      </div>",
  "",
  "      <p class=\"preview-note\" style=\"margin-top:16px;\">Mẫu code tích hợp (dán vào phần xác thực key của app/tool):</p>",
  "      <pre style=\"background:var(--panel-2); border:1px solid var(--line); border-radius:10px; padding:14px; font-family:'JetBrains Mono',monospace; font-size:12px; line-height:1.6; overflow-x:auto; margin:6px 0 0; white-space:pre-wrap; word-break:break-word;\"><code id=\"apiCodeSample\"></code></pre>",
  "    </div>",
  "",
  "    <div class=\"panel\" style=\"margin-top:24px;\">",
  "      <div class=\"panel-head\">",
  "        <div>",
  "          <h2>Ứng dụng / Tool đã kết nối</h2>",
  "          <p class=\"sub\">Hệ thống <b>tự động nhận diện</b> app/tool ngay lần đầu nó gọi link xác thực và đưa vào trạng thái \"Chờ duyệt\". Chỉ ứng dụng được bạn bấm <b>Cho phép</b> mới xác thực key thành công — các app khác sẽ bị server từ chối.</p>",
  "        </div>",
  "        <button class=\"btn btn-ghost btn-inline\" id=\"btnRefreshApps\">Làm mới</button>",
  "      </div>",
  "      <div class=\"table-wrap\">",
  "        <table id=\"apiAppsTable\">",
  "          <thead><tr><th>App ID</th><th>Trạng thái</th><th>Lần gọi cuối</th><th>Tổng lượt kiểm tra</th><th>Hành động</th></tr></thead>",
  "          <tbody></tbody>",
  "        </table>",
  "      </div>",
  "      <div class=\"empty\" id=\"apiAppsEmpty\" style=\"display:none;\">",
  "        <div class=\"big\">Chưa có ứng dụng nào kết nối</div>",
  "        Dán link xác thực vào app/tool của bạn — hệ thống sẽ tự nhận diện và hiện tại đây.",
  "      </div>",
  "    </div>",
  "",
  "    <div class=\"panel\" style=\"margin-top:24px;\">",
  "      <h2>Nhật ký kiểm tra key gần đây</h2>",
  "      <p class=\"sub\">Tối đa 50/200 lượt gọi xác thực gần nhất từ mọi app/tool, lưu trên server.</p>",
  "      <div class=\"table-wrap\">",
  "        <table id=\"apiLogsTable\">",
  "          <thead><tr><th>Thời gian</th><th>App ID</th><th>Key</th><th>Kết quả</th></tr></thead>",
  "          <tbody></tbody>",
  "        </table>",
  "      </div>",
  "    </div>",
  "  </div>",
  "",
  "  <!-- ============ PAGE: SẢN PHẨM (STOREFRONT) & MÃ GIẢM GIÁ ============ -->",
  "  <div id=\"page-products\" style=\"display:none;\">",
  "    <div class=\"sec-note\">",
  "      Trang bán key công khai nằm ở địa chỉ gốc <b>\"/\"</b> của server (khách không cần đăng nhập admin). Sản phẩm bạn tạo ở đây sẽ <b>tự động hiện lên</b> trang bán key ngay khi lưu. Mỗi sản phẩm cần gắn với 1 <b>tiền tố key</b> — hệ thống sẽ tự lấy key <b>còn hàng</b> có tiền tố đó trong kho \"Quản lý Key\" để giao cho khách khi mua thành công.",
  "    </div>",
  "",
  "    <div class=\"panel\" style=\"margin-top:20px;\">",
  "      <h2 id=\"productFormTitle\">Thêm sản phẩm mới</h2>",
  "      <p class=\"sub\">Tuỳ chỉnh tên, logo, giá bán và thời hạn hiển thị cho khách trên trang bán key.</p>",
  "",
  "      <label>Tên sản phẩm</label>",
  "      <input type=\"text\" id=\"prodName\" placeholder=\"VD: Gói PRO 30 ngày\">",
  "",
  "      <label>Logo sản phẩm (chọn ảnh từ điện thoại)</label>",
  "      <div style=\"display:flex; align-items:center; gap:14px; margin-bottom:6px;\">",
  "        <div id=\"prodLogoPreview\" style=\"width:56px; height:56px; border-radius:12px; background:var(--panel-2); border:1px solid var(--line); display:flex; align-items:center; justify-content:center; overflow:hidden; flex-shrink:0;\">",
  "          <svg viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"1.6\" style=\"width:22px; height:22px; color:var(--muted);\"><rect x=\"3\" y=\"3\" width=\"18\" height=\"18\" rx=\"2\"/><circle cx=\"9\" cy=\"9\" r=\"2\"/><path d=\"m21 15-5-5L5 21\"/></svg>",
  "        </div>",
  "        <input type=\"file\" id=\"prodLogoInput\" accept=\"image/*\" style=\"flex:1;\">",
  "      </div>",
  "",
  "      <label>Tiền tố key liên kết (prefix)</label>",
  "      <input type=\"text\" id=\"prodKeyPrefix\" placeholder=\"VD: PRO\" maxlength=\"10\" style=\"text-transform:uppercase;\">",
  "      <p class=\"preview-note\" style=\"margin-top:6px;\">Phải trùng với tiền tố (prefix) bạn dùng khi \"Sinh key ngay\" ở trang Quản lý Key. Còn hàng = key có tiền tố này đang ở trạng thái \"Còn hàng\".</p>",
  "",
  "      <div class=\"row2\">",
  "        <div>",
  "          <label>Giá bán (₫)</label>",
  "          <input type=\"text\" id=\"prodPrice\" placeholder=\"VD: 99000\">",
  "        </div>",
  "        <div>",
  "          <label>Số thiết bị / key (hiển thị cho khách)</label>",
  "          <input type=\"number\" id=\"prodMaxDevices\" value=\"1\" min=\"1\" max=\"20\">",
  "        </div>",
  "      </div>",
  "",
  "      <label>Thời hạn sản phẩm</label>",
  "      <div class=\"chip-toggle\" id=\"prodDurationToggle\">",
  "        <input type=\"radio\" name=\"pdur\" id=\"pdurLimited\" value=\"limited\" checked><label for=\"pdurLimited\">Có thời hạn</label>",
  "        <input type=\"radio\" name=\"pdur\" id=\"pdurUnlimited\" value=\"unlimited\"><label for=\"pdurUnlimited\">Không giới hạn</label>",
  "      </div>",
  "      <div class=\"row2\" id=\"prodDurationFields\" style=\"margin-top:10px;\">",
  "        <div>",
  "          <label>Số lượng</label>",
  "          <input type=\"number\" id=\"prodDurationAmount\" value=\"30\" min=\"1\">",
  "        </div>",
  "        <div>",
  "          <label>Đơn vị</label>",
  "          <select id=\"prodDurationUnit\">",
  "            <option value=\"hour\">Giờ</option>",
  "            <option value=\"day\" selected>Ngày</option>",
  "            <option value=\"month\">Tháng</option>",
  "          </select>",
  "        </div>",
  "      </div>",
  "",
  "      <label style=\"margin-top:14px; display:flex; align-items:center; gap:8px;\"><input type=\"checkbox\" id=\"prodActive\" checked style=\"width:auto;\"> Hiển thị sản phẩm này trên trang bán key</label>",
  "",
  "      <button class=\"btn\" id=\"btnSaveProduct\" style=\"margin-top:16px;\">Lưu sản phẩm</button>",
  "      <button class=\"btn btn-ghost\" id=\"btnCancelEditProduct\" style=\"margin-top:10px; display:none;\">Huỷ chỉnh sửa</button>",
  "    </div>",
  "",
  "    <div class=\"panel\" style=\"margin-top:24px;\">",
  "      <div class=\"panel-head\">",
  "        <div>",
  "          <h2>Danh sách sản phẩm</h2>",
  "          <p class=\"sub\">Quản lý các sản phẩm đang hiển thị trên trang bán key.</p>",
  "        </div>",
  "      </div>",
  "      <div id=\"productList\" style=\"margin-top:14px; display:grid; gap:12px;\"></div>",
  "      <div class=\"empty\" id=\"productEmpty\" style=\"display:none;\">",
  "        <div class=\"big\">Chưa có sản phẩm nào</div>",
  "        Thêm sản phẩm ở form phía trên để bắt đầu bán key.",
  "      </div>",
  "    </div>",
  "",
  "    <div class=\"panel\" style=\"margin-top:24px;\">",
  "      <h2>Thêm mã giảm giá</h2>",
  "      <p class=\"sub\">Mã giảm % trên giá key khi khách thanh toán ở trang bán key.</p>",
  "      <div class=\"row2\">",
  "        <div>",
  "          <label>Mã giảm giá</label>",
  "          <input type=\"text\" id=\"discCode\" placeholder=\"VD: SALE20\" style=\"text-transform:uppercase;\">",
  "        </div>",
  "        <div>",
  "          <label>Phần trăm giảm (%)</label>",
  "          <input type=\"number\" id=\"discPercent\" value=\"10\" min=\"1\" max=\"99\">",
  "        </div>",
  "      </div>",
  "      <div class=\"row2\">",
  "        <div>",
  "          <label>Số lượt dùng tối đa (0 = không giới hạn)</label>",
  "          <input type=\"number\" id=\"discMaxUses\" value=\"0\" min=\"0\">",
  "        </div>",
  "        <div>",
  "          <label>Hạn dùng (tuỳ chọn)</label>",
  "          <input type=\"datetime-local\" id=\"discExpiry\">",
  "        </div>",
  "      </div>",
  "      <button class=\"btn\" id=\"btnAddDiscount\" style=\"margin-top:14px;\">Tạo mã giảm giá</button>",
  "    </div>",
  "",
  "    <div class=\"panel\" style=\"margin-top:24px;\">",
  "      <h2>Danh sách mã giảm giá</h2>",
  "      <div class=\"table-wrap\">",
  "        <table id=\"discountTable\">",
  "          <thead><tr><th>Mã</th><th>Giảm</th><th>Đã dùng</th><th>Hạn dùng</th><th>Trạng thái</th><th>Hành động</th></tr></thead>",
  "          <tbody></tbody>",
  "        </table>",
  "      </div>",
  "      <div class=\"empty\" id=\"discountEmpty\" style=\"display:none;\">",
  "        <div class=\"big\">Chưa có mã giảm giá nào</div>",
  "      </div>",
  "    </div>",
  "",
  "    <!-- ============ NHÓM SẢN PHẨM (1 logo/tên + NHIỀU gói giá, giống GetKey) ============ -->",
  "    <div class=\"sec-note\" style=\"margin-top:32px;\">",
  "      <b>Nhóm sản phẩm</b> cho phép 1 sản phẩm (VD: \"Liên Quân\") hiện <b>1 logo duy nhất</b> trên trang bán key, khách bấm vào rồi mới chọn 1 trong nhiều gói giá (VD: 1 ngày 10k, 7 ngày 50k, 1 tháng 150k...). Mỗi gói vẫn cần gắn tiền tố key riêng để hệ thống biết lấy key nào giao cho khách.",
  "    </div>",
  "",
  "    <div class=\"panel\" style=\"margin-top:20px;\">",
  "      <h2 id=\"pgFormTitle\">Thêm nhóm sản phẩm mới</h2>",
  "      <p class=\"sub\">Tuỳ chỉnh tên, logo và danh sách các gói giá kèm tiền tố key riêng cho từng gói.</p>",
  "",
  "      <label>Tên nhóm sản phẩm</label>",
  "      <input type=\"text\" id=\"pgName\" placeholder=\"VD: Liên Quân Mobile\">",
  "",
  "      <label>Logo (chọn ảnh từ điện thoại)</label>",
  "      <div style=\"display:flex; align-items:center; gap:14px; margin-bottom:6px;\">",
  "        <div id=\"pgLogoPreview\" style=\"width:56px; height:56px; border-radius:12px; background:var(--panel-2); border:1px solid var(--line); display:flex; align-items:center; justify-content:center; overflow:hidden; flex-shrink:0;\">",
  "          <svg viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"1.6\" style=\"width:22px; height:22px; color:var(--muted);\"><rect x=\"3\" y=\"3\" width=\"18\" height=\"18\" rx=\"2\"/><circle cx=\"9\" cy=\"9\" r=\"2\"/><path d=\"m21 15-5-5L5 21\"/></svg>",
  "        </div>",
  "        <input type=\"file\" id=\"pgLogoInput\" accept=\"image/*\" style=\"flex:1;\">",
  "      </div>",
  "",
  "      <label style=\"margin-top:14px; display:flex; align-items:center; gap:8px;\"><input type=\"checkbox\" id=\"pgActive\" checked style=\"width:auto;\"> Hiển thị nhóm sản phẩm này trên trang bán key</label>",
  "",
  "      <div class=\"panel\" style=\"margin-top:18px; background:var(--panel-2);\">",
  "        <div class=\"panel-head\">",
  "          <h2 style=\"font-size:15px;\">Các gói giá trong nhóm</h2>",
  "          <button class=\"btn btn-ghost btn-inline\" id=\"btnAddPgPlan\">+ Thêm gói</button>",
  "        </div>",
  "        <div id=\"pgPlanList\" style=\"display:grid; gap:10px; margin-top:10px;\"></div>",
  "      </div>",
  "",
  "      <button class=\"btn\" id=\"btnSavePg\" style=\"margin-top:16px;\">Lưu nhóm sản phẩm</button>",
  "      <button class=\"btn btn-ghost\" id=\"btnCancelEditPg\" style=\"margin-top:10px; display:none;\">Huỷ chỉnh sửa</button>",
  "    </div>",
  "",
  "    <div class=\"panel\" style=\"margin-top:24px;\">",
  "      <div class=\"panel-head\">",
  "        <div>",
  "          <h2>Danh sách nhóm sản phẩm</h2>",
  "          <p class=\"sub\">Quản lý các nhóm sản phẩm đang hiển thị trên trang bán key.</p>",
  "        </div>",
  "        <button class=\"btn btn-ghost btn-inline\" id=\"btnRefreshPg\">Làm mới</button>",
  "      </div>",
  "      <div id=\"pgList\" style=\"margin-top:14px; display:grid; gap:12px;\"></div>",
  "      <div class=\"empty\" id=\"pgEmpty\" style=\"display:none;\">",
  "        <div class=\"big\">Chưa có nhóm sản phẩm nào</div>",
  "        Thêm ở form phía trên để bắt đầu bán theo nhiều gói giá.",
  "      </div>",
  "    </div>",
  "  </div>",
  "",
  "  <!-- ============ PAGE: GETKEY (VƯỢT LINK NHẬN KEY) ============ -->",
  "  <div id=\"page-getkey\" style=\"display:none;\">",
  "    <div class=\"sec-note\">",
  "      Trang \"GetKey\" cho phép khách <b>vượt link</b> để nhận key miễn phí thay vì mua bằng tiền. Mỗi game bạn tạo ở đây sẽ hiện lên mục \"GetKey\" trên trang bán key (\"/\"). Mỗi loại thời hạn (VD 12 giờ, 24 giờ...) có thể tuỳ chỉnh <b>số lượt vượt link</b> riêng — khách phải vượt đủ số lượt mới nhận được key. Link vượt được tạo thật qua API <b>LAYMA.NET</b> (token đã cấu hình sẵn ở server).",
  "    </div>",
  "",
  "    <div class=\"panel\" style=\"margin-top:20px;\">",
  "      <h2 id=\"getKeyFormTitle\">Thêm game GetKey mới</h2>",
  "      <p class=\"sub\">Tuỳ chỉnh tên game, tiền tố key liên kết và các loại thời hạn kèm số lượt vượt link.</p>",
  "",
  "      <label>Tên game</label>",
  "      <input type=\"text\" id=\"gkName\" placeholder=\"VD: Free Fire\">",
  "",
  "      <label>Logo game (chọn ảnh từ điện thoại)</label>",
  "      <div style=\"display:flex; align-items:center; gap:14px; margin-bottom:6px;\">",
  "        <div id=\"gkLogoPreview\" style=\"width:56px; height:56px; border-radius:12px; background:var(--panel-2); border:1px solid var(--line); display:flex; align-items:center; justify-content:center; overflow:hidden; flex-shrink:0;\">",
  "          <svg viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"1.6\" style=\"width:22px; height:22px; color:var(--muted);\"><rect x=\"3\" y=\"3\" width=\"18\" height=\"18\" rx=\"2\"/><circle cx=\"9\" cy=\"9\" r=\"2\"/><path d=\"m21 15-5-5L5 21\"/></svg>",
  "        </div>",
  "        <input type=\"file\" id=\"gkLogoInput\" accept=\"image/*\" style=\"flex:1;\">",
  "      </div>",
  "",
  "      <label>Tiền tố key liên kết (prefix)</label>",
  "      <input type=\"text\" id=\"gkKeyPrefix\" placeholder=\"VD: FF\" maxlength=\"10\" style=\"text-transform:uppercase;\">",
  "      <p class=\"preview-note\" style=\"margin-top:6px;\">Phải trùng với tiền tố (prefix) bạn dùng khi \"Sinh key ngay\" ở trang Quản lý Key.</p>",
  "",
  "      <label style=\"margin-top:14px; display:flex; align-items:center; gap:8px;\"><input type=\"checkbox\" id=\"gkActive\" checked style=\"width:auto;\"> Hiển thị game này trên trang GetKey</label>",
  "",
  "      <div class=\"panel-head\" style=\"margin-top:20px;\">",
  "        <div>",
  "          <h2 style=\"font-size:15px;\">Các loại thời hạn &amp; số lượt vượt link</h2>",
  "          <p class=\"sub\">VD: chọn key 12 giờ sẽ vượt 2 lượt, chọn key 24 giờ sẽ vượt 3 lượt.</p>",
  "        </div>",
  "        <button class=\"btn btn-ghost btn-inline\" id=\"btnAddGkDuration\">+ Thêm loại</button>",
  "      </div>",
  "      <div id=\"gkDurationList\" style=\"display:grid; gap:10px; margin-top:10px;\"></div>",
  "",
  "      <button class=\"btn\" id=\"btnSaveGetKeyGame\" style=\"margin-top:16px;\">Lưu game GetKey</button>",
  "      <button class=\"btn btn-ghost\" id=\"btnCancelEditGetKeyGame\" style=\"margin-top:10px; display:none;\">Huỷ chỉnh sửa</button>",
  "    </div>",
  "",
  "    <div class=\"panel\" style=\"margin-top:24px;\">",
  "      <div class=\"panel-head\">",
  "        <div>",
  "          <h2>Danh sách game GetKey</h2>",
  "          <p class=\"sub\">Quản lý các game đang hiển thị trên trang GetKey.</p>",
  "        </div>",
  "        <button class=\"btn btn-ghost btn-inline\" id=\"btnRefreshGetKeyGames\">Làm mới</button>",
  "      </div>",
  "      <div id=\"getKeyGameList\" style=\"margin-top:14px; display:grid; gap:12px;\"></div>",
  "      <div class=\"empty\" id=\"getKeyGameEmpty\" style=\"display:none;\">",
  "        <div class=\"big\">Chưa có game GetKey nào</div>",
  "        Thêm game ở form phía trên để bắt đầu cho khách vượt link nhận key.",
  "      </div>",
  "    </div>",
  "  </div>",
  "",
  "</main>",
  "",
  "<footer>KeyVault — Hệ thống bảo mật · an toàn · chất lượng. Dữ liệu được tự động mã hoá &amp; lưu trữ trên máy chủ.</footer>",
  "",
  "</div><!-- /#appRoot -->",
  "",
  "<div class=\"toast\" id=\"toast\"></div>",
  "",
  "<div class=\"modal-bg\" id=\"sellModalBg\">",
  "  <div class=\"modal\">",
  "    <h3>Đánh dấu đã bán</h3>",
  "    <label>Tên / liên hệ khách hàng</label>",
  "    <input type=\"text\" id=\"sellCustomer\" placeholder=\"VD: Nguyễn Văn A - zalo 09xx\">",
  "    <label>Giá bán (₫)</label>",
  "    <input type=\"text\" id=\"sellPrice\" placeholder=\"VD: 99000\">",
  "    <label>Mã thiết bị kích hoạt (tuỳ chọn)</label>",
  "    <input type=\"text\" id=\"sellDevice\" placeholder=\"VD: DEVICE-8F21A\">",
  "    <div class=\"modal-actions\">",
  "      <button class=\"btn btn-ghost\" id=\"sellCancel\">Huỷ</button>",
  "      <button class=\"btn\" id=\"sellConfirm\">Xác nhận</button>",
  "    </div>",
  "  </div>",
  "</div>",
  "",
  "<div class=\"modal-bg\" id=\"extendModalBg\">",
  "  <div class=\"modal\">",
  "    <h3>Gia hạn tài khoản</h3>",
  "    <p class=\"sub\" id=\"extendSellerLabel\" style=\"margin-top:-6px;\"></p>",
  "    <div class=\"row2\">",
  "      <div>",
  "        <label>Số lượng</label>",
  "        <input type=\"number\" id=\"extendAmount\" value=\"30\" min=\"1\">",
  "      </div>",
  "      <div>",
  "        <label>Đơn vị</label>",
  "        <select id=\"extendUnit\">",
  "          <option value=\"hour\">Giờ</option>",
  "          <option value=\"day\" selected>Ngày</option>",
  "          <option value=\"month\">Tháng</option>",
  "        </select>",
  "      </div>",
  "    </div>",
  "    <div class=\"modal-actions\">",
  "      <button class=\"btn btn-ghost\" id=\"extendCancel\">Huỷ</button>",
  "      <button class=\"btn\" id=\"extendConfirm\">Cộng thời gian</button>",
  "    </div>",
  "  </div>",
  "</div>",
  "",
  "<div class=\"modal-bg\" id=\"extendAllModalBg\">",
  "  <div class=\"modal\">",
  "    <h3>⏱ Gia hạn tất cả key</h3>",
  "    <p class=\"sub\" style=\"margin-top:-6px;\">Cộng thêm thời gian đã chọn vào hạn dùng của TẤT CẢ key có thời hạn (áp dụng cho key đã kích hoạt lẫn key chưa kích hoạt, ở tất cả tài khoản).</p>",
  "    <div class=\"row2\">",
  "      <div>",
  "        <label>Số lượng</label>",
  "        <input type=\"number\" id=\"extendAllAmount\" value=\"1\" min=\"1\">",
  "      </div>",
  "      <div>",
  "        <label>Đơn vị</label>",
  "        <select id=\"extendAllUnit\">",
  "          <option value=\"hour\">Giờ</option>",
  "          <option value=\"day\" selected>Ngày</option>",
  "          <option value=\"month\">Tháng</option>",
  "        </select>",
  "      </div>",
  "    </div>",
  "    <p class=\"preview-note\" id=\"extendAllPreviewNote\" style=\"margin-top:10px;\"></p>",
  "    <div class=\"modal-actions\">",
  "      <button class=\"btn btn-ghost\" id=\"extendAllCancel\">Huỷ</button>",
  "      <button class=\"btn\" id=\"extendAllConfirm\">Gia hạn thời gian</button>",
  "    </div>",
  "  </div>",
  "</div>",
  "",
  "<div class=\"modal-bg\" id=\"topupModalBg\">",
  "  <div class=\"modal\">",
  "    <h3>Thêm tiền cho tài khoản</h3>",
  "    <p class=\"sub\" id=\"topupSellerLabel\" style=\"margin-top:-6px;\"></p>",
  "    <label>Số tiền cộng thêm (₫)</label>",
  "    <input type=\"text\" id=\"topupAmount\" placeholder=\"VD: 100000\">",
  "    <div class=\"modal-actions\">",
  "      <button class=\"btn btn-ghost\" id=\"topupCancel\">Huỷ</button>",
  "      <button class=\"btn\" id=\"topupConfirm\">Cộng tiền</button>",
  "    </div>",
  "  </div>",
  "</div>",
  "",
  "<div class=\"modal-bg\" id=\"sellerPassModalBg\">",
  "  <div class=\"modal\">",
  "    <h3>Đổi mật khẩu người bán</h3>",
  "    <p class=\"sub\" id=\"sellerPassLabel\" style=\"margin-top:-6px;\"></p>",
  "    <label>Mật khẩu mới</label>",
  "    <input type=\"text\" id=\"sellerPassNew\" placeholder=\"Nhập mật khẩu mới\">",
  "    <div class=\"modal-actions\">",
  "      <button class=\"btn btn-ghost\" id=\"sellerPassCancel\">Huỷ</button>",
  "      <button class=\"btn\" id=\"sellerPassConfirm\">Đổi mật khẩu</button>",
  "    </div>",
  "  </div>",
  "</div>",
  "",
  "<div class=\"modal-bg\" id=\"customerTopupModalBg\">",
  "  <div class=\"modal\">",
  "    <h3>Thêm tiền cho người dùng</h3>",
  "    <p class=\"sub\" id=\"customerTopupLabel\" style=\"margin-top:-6px;\"></p>",
  "    <label>Số tiền cộng thêm (₫)</label>",
  "    <input type=\"text\" id=\"customerTopupAmount\" placeholder=\"VD: 100000\">",
  "    <div class=\"modal-actions\">",
  "      <button class=\"btn btn-ghost\" id=\"customerTopupCancel\">Huỷ</button>",
  "      <button class=\"btn\" id=\"customerTopupConfirm\">Cộng tiền</button>",
  "    </div>",
  "  </div>",
  "</div>",
  "",
  "<div class=\"modal-bg\" id=\"customerPassModalBg\">",
  "  <div class=\"modal\">",
  "    <h3>Đổi mật khẩu người dùng</h3>",
  "    <p class=\"sub\" id=\"customerPassLabel\" style=\"margin-top:-6px;\"></p>",
  "    <label>Mật khẩu mới</label>",
  "    <input type=\"text\" id=\"customerPassNew\" placeholder=\"Nhập mật khẩu mới (tối thiểu 4 ký tự)\">",
  "    <div class=\"modal-actions\">",
  "      <button class=\"btn btn-ghost\" id=\"customerPassCancel\">Huỷ</button>",
  "      <button class=\"btn\" id=\"customerPassConfirm\">Đổi mật khẩu</button>",
  "    </div>",
  "  </div>",
  "</div>",
  "",
  "<div class=\"modal-bg\" id=\"ownPassModalBg\">",
  "  <div class=\"modal\">",
  "    <h3>Đổi mật khẩu tài khoản</h3>",
  "    <p class=\"sub\" id=\"ownPassLabel\" style=\"margin-top:-6px;\"></p>",
  "    <label>Mật khẩu hiện tại</label>",
  "    <input type=\"text\" id=\"ownPassCurrent\" placeholder=\"Nhập mật khẩu hiện tại\">",
  "    <label>Mật khẩu mới</label>",
  "    <input type=\"text\" id=\"ownPassNew\" placeholder=\"Nhập mật khẩu mới\">",
  "    <label>Xác nhận mật khẩu mới</label>",
  "    <input type=\"text\" id=\"ownPassConfirmField\" placeholder=\"Nhập lại mật khẩu mới\">",
  "    <div class=\"modal-actions\">",
  "      <button class=\"btn btn-ghost\" id=\"ownPassCancel\">Huỷ</button>",
  "      <button class=\"btn\" id=\"ownPassConfirm\">Đổi mật khẩu</button>",
  "    </div>",
  "  </div>",
  "</div>",
  "",
  "<div class=\"modal-bg\" id=\"blockIpModalBg\">",
  "  <div class=\"modal\">",
  "    <h3>Chặn IP thủ công</h3>",
  "    <label>Địa chỉ IP</label>",
  "    <input type=\"text\" id=\"blockIpValue\" placeholder=\"VD: 192.168.1.10\">",
  "    <label>Lý do</label>",
  "    <select id=\"blockIpReason\">",
  "      <option>Brute-force đăng nhập nhiều lần</option>",
  "      <option>Quét cổng bất thường</option>",
  "      <option>Gửi yêu cầu bất thường (nghi DDoS)</option>",
  "      <option>User-agent đáng ngờ / bot</option>",
  "      <option>Truy cập endpoint quản trị trái phép</option>",
  "      <option>Vượt giới hạn tốc độ request (rate limit)</option>",
  "      <option>Khác</option>",
  "    </select>",
  "    <div class=\"modal-actions\">",
  "      <button class=\"btn btn-ghost\" id=\"blockIpCancel\">Huỷ</button>",
  "      <button class=\"btn\" id=\"blockIpConfirm\">Chặn IP</button>",
  "    </div>",
  "  </div>",
  "</div>",
  "",
  "<script>",
  "/* ============ LOGIN LOGIC ============ */",
  "const DEMO_USER = 'Adminn';",
  "const DEMO_PASS = '120510@';",
  "let adminPassword = DEMO_PASS; // mật khẩu admin hiện tại — có thể đổi qua nút \"Đổi mật khẩu\"",
  "let loginHistory = []; // chỉ ghi lại các lượt đăng nhập thật diễn ra trong phiên này",
  "",
  "let currentRole = null;      // 'admin' | 'seller'",
  "let currentAccount = null;   // 'admin' hoặc username người bán",
  "let keysStore = {};          // kho key riêng theo từng tài khoản: { admin:[...], dealer01:[...] }",
  "",
  "function showToastLogin(msg){",
  "  const t = document.getElementById('toast');",
  "  t.textContent = msg;",
  "  t.classList.add('show');",
  "  clearTimeout(window._loginToastTimer);",
  "  window._loginToastTimer = setTimeout(()=> t.classList.remove('show'), 2400);",
  "}",
  "",
  "function sellerAccountStatus(s){",
  "  if(s.banned) return 'banned';",
  "  if(s.expiresAt && new Date() > new Date(s.expiresAt)) return 'expired';",
  "  return 'active';",
  "}",
  "",
  "/* ============ BẢNG GIÁ & THỜI HẠN KEY CỐ ĐỊNH (TRỪ VÀO SỐ DƯ NGƯỜI BÁN) ============ */",
  "// Cố định 6 mốc thời hạn + giá theo yêu cầu quản trị viên. Seller/admin KHÔNG được tự",
  "// nhập số lượng + đơn vị tuỳ ý nữa khi tạo key có thời hạn — chỉ chọn 1 trong các mốc",
  "// dưới đây (áp dụng cho cả tài khoản Thường lẫn Premium). Muốn đổi giá/thời hạn phải",
  "// sửa mảng FIXED_KEY_PLANS này trực tiếp trong code — không có chỗ nào trên giao diện",
  "// admin/seller cho phép chỉnh sửa các con số này.",
  "const FIXED_KEY_PLANS = [",
  "  { id:'h12',       label:'12 giờ',         unit:'hour',      amount:12,  price:20000  },",
  "  { id:'d1',        label:'1 ngày',         unit:'day',       amount:1,   price:30000  },",
  "  { id:'w1',        label:'1 tuần',         unit:'day',       amount:7,   price:60000  },",
  "  { id:'d15',       label:'15 ngày',        unit:'day',       amount:15,  price:90000  },",
  "  { id:'m1',        label:'1 tháng',        unit:'month',     amount:1,   price:160000 },",
  "  { id:'unlimited', label:'Không giới hạn', unit:'unlimited', amount:null,price:500000 }",
  "];",
  "function findFixedPlan(id){ return FIXED_KEY_PLANS.find(p=>p.id===id) || null; }",
  "",
  "/* Giữ KEY_PRICES để tương thích ngược với code cũ tham chiếu theo đơn vị (hour/day/month/",
  "   unlimited) — giờ được suy ra từ bảng giá cố định phía trên thay vì số rời rạc như trước. */",
  "const KEY_PRICES = { hour: findFixedPlan('h12').price, day: findFixedPlan('d1').price, month: findFixedPlan('m1').price, unlimited: findFixedPlan('unlimited').price };",
  "",
  "// [KHÔNG CÒN ÁP DỤNG cho bảng giá cố định mới — giữ nguyên hàm cũ để không xoá code cũ]",
  "// Ưu đãi theo \"tuổi\" tài khoản người bán (tính từ lúc admin tạo tài khoản):",
  "// > 5 giờ hoạt động -> giảm 20%; > 3 ngày hoạt động -> giảm thêm 20% trên số tiền còn lại (dồn ~36%).",
  "function sellerDiscountFactor(seller){",
  "  if(!seller || !seller.createdAt) return 1;",
  "  const ageMs = new Date() - new Date(seller.createdAt);",
  "  let factor = 1;",
  "  if(ageMs >= 5*3600000) factor *= 0.8;",
  "  if(ageMs >= 3*86400000) factor *= 0.8;",
  "  return factor;",
  "}",
  "function sellerDiscountPercent(seller){",
  "  return Math.round((1 - sellerDiscountFactor(seller)) * 100);",
  "}",
  "function keyUnitCost(unitOrUnlimited){",
  "  return KEY_PRICES[unitOrUnlimited] ?? 0;",
  "}",
  "",
  "function doLogin(){",
  "  const user = document.getElementById('loginUser').value.trim();",
  "  const pass = document.getElementById('loginPass').value.trim();",
  "  const errBox = document.getElementById('loginError');",
  "",
  "  let success = false;",
  "  let role = null;",
  "  let errMsg = 'Sai tên đăng nhập hoặc mật khẩu.';",
  "",
  "  if(user === DEMO_USER && pass === adminPassword){",
  "    success = true; role = 'admin';",
  "  } else {",
  "    const s = sellers.find(x=>x.username === user);",
  "    if(s && s.password === pass){",
  "      const st = sellerAccountStatus(s);",
  "      if(st === 'banned'){",
  "        errMsg = 'Tài khoản đã bị cấm.';",
  "      } else if(st === 'expired'){",
  "        errMsg = 'Tài khoản đã hết hạn sử dụng.';",
  "      } else {",
  "        success = true; role = 'seller';",
  "      }",
  "    }",
  "  }",
  "",
  "  loginHistory.unshift({time:new Date(), user: user || '(trống)', success});",
  "",
  "  if(success){",
  "    errBox.classList.remove('show');",
  "",
  "    /* ---- Auto lưu đăng nhập: mỗi lần đăng nhập thành công, tự động lưu tài khoản/mật khẩu",
  "       vào localStorage của trình duyệt để lần sau vào lại tự động điền sẵn (không cần tick gì cả) ---- */",
  "    try{",
  "      localStorage.setItem('keyvault_remember', JSON.stringify({ user, pass }));",
  "    }catch(e){ /* trình duyệt chặn localStorage cũng không sao, chỉ là không tự điền lại được */ }",
  "",
  "    currentRole = role;",
  "    currentAccount = role === 'admin' ? 'admin' : user;",
  "    if(!keysStore[currentAccount]) keysStore[currentAccount] = [];",
  "    keys = keysStore[currentAccount];",
  "",
  "    document.getElementById('loginScreen').style.display = 'none';",
  "    document.getElementById('appRoot').style.display = 'block';",
  "    applyRoleVisibility();",
  "    render();",
  "",
  "    if(role === 'seller'){",
  "      const s = sellers.find(x=>x.username===currentAccount);",
  "      const unread = (s && s.notifications) ? s.notifications.filter(n=>!n.read) : [];",
  "      if(unread.length){",
  "        showToast(unread.length===1 ? unread[0].message : `Bạn có ${unread.length} thông báo mới từ quản trị viên`);",
  "      }",
  "    }",
  "  } else {",
  "    errBox.textContent = errMsg;",
  "    errBox.classList.add('show');",
  "  }",
  "}",
  "",
  "function applyRoleVisibility(){",
  "  document.querySelectorAll('.tab-btn').forEach(btn=>{",
  "    const adminOnly = btn.dataset.adminOnly === '1';",
  "    const isKeysTab = btn.dataset.page === 'keys';",
  "    if(currentRole === 'seller'){",
  "      btn.style.display = isKeysTab ? '' : 'none';",
  "    } else {",
  "      btn.style.display = '';",
  "    }",
  "  });",
  "  document.querySelectorAll('[data-admin-only=\"1\"]').forEach(el=>{",
  "    if(el.classList.contains('tab-btn')) return; // đã xử lý ở trên",
  "    el.style.display = currentRole === 'admin' ? '' : 'none';",
  "  });",
  "  if(currentRole === 'seller'){",
  "    document.querySelectorAll('.tab-btn').forEach(b=>b.classList.remove('active'));",
  "    document.querySelector('.tab-btn[data-page=\"keys\"]').classList.add('active');",
  "    currentPage = 'keys';",
  "    document.getElementById('page-keys').style.display = 'grid';",
  "    document.getElementById('page-stats').style.display = 'none';",
  "    document.getElementById('page-security').style.display = 'none';",
  "    document.getElementById('page-sellers').style.display = 'none';",
  "    document.getElementById('page-customers').style.display = 'none';",
  "    document.getElementById('page-apikey').style.display = 'none';",
  "    document.getElementById('page-products').style.display = 'none';",
  "    document.getElementById('page-getkey').style.display = 'none';",
  "    // seller luôn dùng thời gian hiện tại khi tạo key",
  "    document.getElementById('createdAtNow').checked = true;",
  "    document.getElementById('createdAtCustomField').style.display = 'none';",
  "  }",
  "",
  "  applySellerAccountEffects();",
  "}",
  "",
  "/* ============ HIỆU ỨNG / GIỚI HẠN THEO LOẠI TÀI KHOẢN NGƯỜI BÁN (THƯỜNG / PREMIUM) ============ */",
  "function applySellerAccountEffects(){",
  "  const isSeller = currentRole === 'seller';",
  "  const s = isSeller ? sellers.find(x=>x.username===currentAccount) : null;",
  "  const isPremium = !!(s && s.accountType === 'premium');",
  "",
  "  document.body.classList.toggle('vip-mode', isSeller && isPremium);",
  "  document.getElementById('vipBadge').style.display = (isSeller && isPremium) ? '' : 'none';",
  "",
  "  document.getElementById('statBalanceWrap').style.display = isSeller ? '' : 'none';",
  "  document.getElementById('statAcctExpiryWrap').style.display = isSeller ? '' : 'none';",
  "  document.getElementById('sellerPriceNote').style.display = isSeller ? '' : 'none';",
  "  document.getElementById('sellerNotifPanel').style.display = isSeller ? '' : 'none';",
  "",
  "  const expNoneInput = document.getElementById('expNone');",
  "  const expLimitedInput = document.getElementById('expLimited');",
  "  const lockNote = document.getElementById('expiryLockNote');",
  "  if(isSeller && !isPremium){",
  "    // Tài khoản Thường: khoá tính năng tạo key \"không giới hạn\"",
  "    expNoneInput.disabled = true;",
  "    if(expNoneInput.checked){",
  "      expLimitedInput.checked = true;",
  "    }",
  "    lockNote.style.display = '';",
  "  } else {",
  "    expNoneInput.disabled = false;",
  "    lockNote.style.display = 'none';",
  "  }",
  "",
  "  if(isSeller){",
  "    document.getElementById('statBalance').textContent = fmtMoney((s&&s.balance)||0) || '0₫';",
  "    document.getElementById('statAcctExpiry').textContent = formatRemaining(s && s.expiresAt);",
  "  }",
  "",
  "  renderNotifPanel();",
  "}",
  "",
  "function renderNotifPanel(){",
  "  const box = document.getElementById('notifList');",
  "  if(!box) return;",
  "  const isSeller = currentRole === 'seller';",
  "  if(!isSeller){ box.innerHTML = ''; return; }",
  "  const s = sellers.find(x=>x.username===currentAccount);",
  "  const notifications = (s && s.notifications) || [];",
  "  if(!notifications.length){",
  "    box.innerHTML = '<p class=\"preview-note\" style=\"margin:0;\">Chưa có thông báo nào.</p>';",
  "    return;",
  "  }",
  "  box.innerHTML = notifications.map(n => `",
  "    <div class=\"notif-item ${n.read ? '' : 'unread'}\">",
  "      <div class=\"dot\"></div>",
  "      <div class=\"body\">",
  "        <div class=\"msg\">${n.message}</div>",
  "        <div class=\"time\">${formatDateTime(n.time)}</div>",
  "      </div>",
  "    </div>",
  "  `).join('');",
  "}",
  "",
  "document.getElementById('btnLogin').addEventListener('click', doLogin);",
  "['loginUser','loginPass'].forEach(id=>{",
  "  document.getElementById(id).addEventListener('keydown', (e)=>{ if(e.key==='Enter') doLogin(); });",
  "});",
  "",
  "/* ---- Tự động điền lại tài khoản/mật khẩu đã \"Ghi nhớ\" ở lần đăng nhập trước ---- */",
  "(function autofillRememberedLogin(){",
  "  try{",
  "    const saved = localStorage.getItem('keyvault_remember');",
  "    if(!saved) return;",
  "    const { user, pass, autoLogin } = JSON.parse(saved);",
  "    if(user) document.getElementById('loginUser').value = user;",
  "    if(pass) document.getElementById('loginPass').value = pass;",
  "    /* ---- Gộp đăng nhập: nếu vừa được chuyển hướng từ trang bán key (đăng nhập đúng",
  "       tài khoản admin/seller ở đó), tự bấm đăng nhập luôn — không bắt gõ lại lần 2.",
  "       Cờ 'autoLogin' chỉ dùng đúng 1 lần rồi xoá để lần load /admin sau không tự",
  "       đăng nhập lại nếu người dùng đã cố tình đăng xuất. ---- */",
  "    if(autoLogin){",
  "      localStorage.setItem('keyvault_remember', JSON.stringify({ user, pass }));",
  "      doLogin();",
  "    }",
  "  }catch(e){ /* dữ liệu ghi nhớ lỗi thì bỏ qua, không chặn đăng nhập bình thường */ }",
  "})();",
  "",
  "document.getElementById('btnLogout').addEventListener('click', ()=>{",
  "  document.getElementById('appRoot').style.display = 'none';",
  "  document.getElementById('loginScreen').style.display = 'flex';",
  "  document.getElementById('loginUser').value = '';",
  "  document.getElementById('loginPass').value = '';",
  "  document.getElementById('loginError').classList.remove('show');",
  "  currentRole = null;",
  "  currentAccount = null;",
  "  document.body.classList.remove('vip-mode');",
  "  document.getElementById('vipBadge').style.display = 'none';",
  "  try{ localStorage.removeItem('keyvault_remember'); }catch(e){ /* không sao nếu trình duyệt chặn */ }",
  "});",
  "",
  "/* ============ ẨN/HIỆN 4 CHỈ SỐ PHỤ (ĐÃ BÁN / HẾT HẠN / BỊ CẤM / DOANH THU) ============ */",
  "let statsHidden = false;",
  "document.getElementById('btnToggleStats').addEventListener('click', ()=>{",
  "  statsHidden = !statsHidden;",
  "  document.querySelectorAll('.stat-toggleable').forEach(el=>{",
  "    el.style.display = statsHidden ? 'none' : '';",
  "  });",
  "  document.getElementById('iconEyeOpen').style.display = statsHidden ? 'none' : '';",
  "  document.getElementById('iconEyeClosed').style.display = statsHidden ? '' : 'none';",
  "  document.getElementById('toggleStatsLabel').textContent = statsHidden ? 'Hiện số liệu' : 'Ẩn số liệu';",
  "  document.getElementById('btnToggleStats').classList.toggle('active', statsHidden);",
  "});",
  "",
  "/* ============ ĐỔI MẬT KHẨU TÀI KHOẢN ĐANG ĐĂNG NHẬP ============ */",
  "document.getElementById('btnChangeOwnPassword').addEventListener('click', ()=>{",
  "  document.getElementById('ownPassLabel').textContent = 'Tài khoản: ' + currentAccount + (currentRole==='admin' ? ' (quản trị viên)' : ' (người bán)');",
  "  document.getElementById('ownPassCurrent').value = '';",
  "  document.getElementById('ownPassNew').value = '';",
  "  document.getElementById('ownPassConfirmField').value = '';",
  "  document.getElementById('ownPassModalBg').classList.add('show');",
  "});",
  "document.getElementById('ownPassCancel').addEventListener('click', ()=> document.getElementById('ownPassModalBg').classList.remove('show'));",
  "document.getElementById('ownPassConfirm').addEventListener('click', ()=>{",
  "  const current = document.getElementById('ownPassCurrent').value;",
  "  const next = document.getElementById('ownPassNew').value;",
  "  const confirmVal = document.getElementById('ownPassConfirmField').value;",
  "",
  "  const actualCurrent = currentRole === 'admin' ? adminPassword : (sellers.find(s=>s.username===currentAccount)||{}).password;",
  "",
  "  if(current !== actualCurrent){",
  "    showToast('Mật khẩu hiện tại không đúng'); return;",
  "  }",
  "  if(!next){",
  "    showToast('Vui lòng nhập mật khẩu mới'); return;",
  "  }",
  "  if(next !== confirmVal){",
  "    showToast('Xác nhận mật khẩu mới không khớp'); return;",
  "  }",
  "",
  "  if(currentRole === 'admin'){",
  "    adminPassword = next;",
  "  } else {",
  "    const s = sellers.find(x=>x.username===currentAccount);",
  "    if(s) s.password = next;",
  "  }",
  "  document.getElementById('ownPassModalBg').classList.remove('show');",
  "  showToast('Đã đổi mật khẩu thành công');",
  "});",
  "",
  "/* ============ TAB NAVIGATION ============ */",
  "let currentPage = 'keys';",
  "document.querySelectorAll('.tab-btn').forEach(btn=>{",
  "  btn.addEventListener('click', ()=>{",
  "    document.querySelectorAll('.tab-btn').forEach(b=>b.classList.remove('active'));",
  "    btn.classList.add('active');",
  "    currentPage = btn.dataset.page;",
  "    document.getElementById('page-keys').style.display = currentPage==='keys' ? 'grid' : 'none';",
  "    document.getElementById('page-stats').style.display = currentPage==='stats' ? 'block' : 'none';",
  "    document.getElementById('page-security').style.display = currentPage==='security' ? 'block' : 'none';",
  "    document.getElementById('page-sellers').style.display = currentPage==='sellers' ? 'block' : 'none';",
  "    document.getElementById('page-customers').style.display = currentPage==='customers' ? 'block' : 'none';",
  "    document.getElementById('page-apikey').style.display = currentPage==='apikey' ? 'block' : 'none';",
  "    document.getElementById('page-products').style.display = currentPage==='products' ? 'block' : 'none';",
  "    document.getElementById('page-getkey').style.display = currentPage==='getkey' ? 'block' : 'none';",
  "    if(currentPage==='stats') renderStatsPage();",
  "    if(currentPage==='security') renderSecurityPage();",
  "    if(currentPage==='sellers') renderSellersPage();",
  "    if(currentPage==='customers'){ loadAndRenderCustomersPage(); if(typeof renderSepaySettings==='function') renderSepaySettings(); }",
  "    if(currentPage==='apikey') renderApiKeyPage();",
  "    if(currentPage==='products'){ renderProductsPage(); renderProductGroupsPage(); }",
  "    if(currentPage==='getkey') renderGetKeyPage();",
  "  });",
  "});",
  "",
  "/* ============ SẢN PHẨM (STOREFRONT) & MÃ GIẢM GIÁ (ADMIN ONLY) ============ */",
  "let products = []; // {id, name, logo(dataURL), price, durationAmount, durationUnit, keyPrefix, maxDevices, active, createdAt}",
  "let discountCodes = []; // {id, code, percent, maxUses, usedCount, expiresAt, active, createdAt}",
  "let bankInfo = { bankId:'MB', accountNo:'0364837118', accountName:'LUONG VAN TUYEN' }; // thông tin ngân hàng dùng để sinh QR nạp tiền",
  "let sepayConfig = { enabled:false, apiKey:'' }; // cấu hình đối soát tự động qua webhook SePay",
  "",
  "/* ============ SELLER ACCOUNT MANAGEMENT (ADMIN ONLY) ============ */",
  "let sellers = []; // {id, username, password, createdAt, expiresAt, banned, balance}",
  "let extendTargetId = null;",
  "let topupTargetId = null;",
  "let sellerPassTargetId = null;",
  "",
  "document.querySelectorAll('#sellerExpiryToggle input').forEach(el=>{",
  "  el.addEventListener('change', ()=>{",
  "    document.getElementById('sellerExpiryFields').style.display = document.getElementById('sellerExpLimited').checked ? 'grid' : 'none';",
  "  });",
  "});",
  "",
  "function computeExpiryFrom(base, amount, unit){",
  "  const msPerUnit = unit==='hour' ? 3600000 : unit==='day' ? 86400000 : 30*86400000;",
  "  return new Date(base.getTime() + amount*msPerUnit);",
  "}",
  "",
  "document.getElementById('btnCreateSeller').addEventListener('click', ()=>{",
  "  const username = document.getElementById('sellerUsername').value.trim();",
  "  const password = document.getElementById('sellerPassword').value.trim();",
  "  if(!username || !password){ showToast('Vui lòng nhập tên đăng nhập và mật khẩu'); return; }",
  "  if(username === DEMO_USER || sellers.some(s=>s.username===username)){",
  "    showToast('Tên đăng nhập đã tồn tại'); return;",
  "  }",
  "",
  "  let expiresAt = null;",
  "  if(document.getElementById('sellerExpLimited').checked){",
  "    const amount = Math.max(1, parseFloat(document.getElementById('sellerExpiryAmount').value) || 1);",
  "    const unit = document.getElementById('sellerExpiryUnit').value;",
  "    expiresAt = computeExpiryFrom(new Date(), amount, unit);",
  "  }",
  "",
  "  const initialBalance = parseFloat(String(document.getElementById('sellerInitialBalance').value).replace(/[^\\d.]/g,'')) || 0;",
  "  const accountType = document.getElementById('sellerAcctPremium').checked ? 'premium' : 'normal';",
  "",
  "  const notifications = [];",
  "  if(initialBalance > 0){",
  "    notifications.push({",
  "      id:'n'+Date.now()+Math.random().toString(36).slice(2,7),",
  "      message:`Quản trị viên đã cấp số dư khởi tạo ${fmtMoney(initialBalance)} cho tài khoản của bạn.`,",
  "      time:new Date(), read:false",
  "    });",
  "  }",
  "",
  "  sellers.unshift({",
  "    id: 's'+Date.now()+Math.random().toString(36).slice(2,7),",
  "    username, password,",
  "    createdAt: new Date(),",
  "    expiresAt,",
  "    banned: false,",
  "    balance: initialBalance,",
  "    accountType,",
  "    notifications",
  "  });",
  "  keysStore[username] = keysStore[username] || [];",
  "",
  "  document.getElementById('sellerUsername').value = '';",
  "  document.getElementById('sellerPassword').value = '';",
  "  document.getElementById('sellerInitialBalance').value = '';",
  "  document.getElementById('sellerAcctNormal').checked = true;",
  "  renderSellersPage();",
  "  showToast('Đã tạo tài khoản người bán: '+username);",
  "});",
  "",
  "function renderSellersPage(){",
  "  const tbody = document.querySelector('#sellerTable tbody');",
  "  tbody.innerHTML = '';",
  "  document.getElementById('sellerEmptyState').style.display = sellers.length ? 'none' : 'block';",
  "",
  "  const SELLER_STATUS_LABEL = {active:'Hoạt động', banned:'Bị cấm', expired:'Hết hạn'};",
  "  sellers.forEach(s=>{",
  "    const st = sellerAccountStatus(s);",
  "    const acctType = s.accountType || 'normal';",
  "    const tr = document.createElement('tr');",
  "    const keyCount = (keysStore[s.username]||[]).length;",
  "    tr.innerHTML = `",
  "      <td class=\"mono\">${s.username}</td>",
  "      <td>${formatDateTime(s.createdAt)}</td>",
  "      <td>${s.expiresAt ? formatDateTime(s.expiresAt) : 'Không giới hạn'}</td>",
  "      <td>${formatRemaining(s.expiresAt)}</td>",
  "      <td><span class=\"badge ${st}\">${SELLER_STATUS_LABEL[st]}</span></td>",
  "      <td><span class=\"badge acct ${acctType}\">${acctType==='premium' ? '★ Premium' : 'Thường'}</span></td>",
  "      <td class=\"mono stat-balance\">${fmtMoney(s.balance||0) || '0₫'}</td>",
  "      <td>${keyCount}</td>",
  "      <td>",
  "        <div class=\"actions\">",
  "          <button class=\"icon-btn\" title=\"${acctType==='premium' ? 'Hạ về tài khoản Thường' : 'Nâng cấp lên Premium'}\" data-act=\"togglepremium\" data-id=\"${s.id}\">",
  "            <svg viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"1.7\"><path d=\"M12 2l2.6 6.6L21 9.3l-5 4.7L17.4 21 12 17.3 6.6 21 8 14l-5-4.7 6.4-.7L12 2Z\"/></svg>",
  "          </button>",
  "          <button class=\"icon-btn\" title=\"Thêm tiền cho tài khoản\" data-act=\"topup\" data-id=\"${s.id}\">",
  "            <svg viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"1.7\"><circle cx=\"12\" cy=\"12\" r=\"9\"/><path d=\"M12 8v8M8 12h8\"/></svg>",
  "          </button>",
  "          <button class=\"icon-btn\" title=\"Đổi mật khẩu\" data-act=\"changepass\" data-id=\"${s.id}\">",
  "            <svg viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"1.7\"><rect x=\"5\" y=\"11\" width=\"14\" height=\"9\" rx=\"2\"/><path d=\"M8 11V7a4 4 0 0 1 8 0v4\"/></svg>",
  "          </button>",
  "          <button class=\"icon-btn\" title=\"Thêm thời gian\" data-act=\"extend\" data-id=\"${s.id}\">",
  "            <svg viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"1.7\"><circle cx=\"12\" cy=\"12\" r=\"9\"/><path d=\"M12 7v5l3 3\"/></svg>",
  "          </button>",
  "          ${s.banned",
  "            ? `<button class=\"icon-btn\" title=\"Bỏ cấm\" data-act=\"unban\" data-id=\"${s.id}\"><svg viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"1.7\"><circle cx=\"12\" cy=\"12\" r=\"9\"/><path d=\"M8 12l3 3 5-6\"/></svg></button>`",
  "            : `<button class=\"icon-btn danger\" title=\"Cấm tài khoản\" data-act=\"ban\" data-id=\"${s.id}\"><svg viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"1.7\"><circle cx=\"12\" cy=\"12\" r=\"9\"/><path d=\"M5.5 5.5l13 13\"/></svg></button>`}",
  "          <button class=\"icon-btn danger\" title=\"Xoá tài khoản\" data-act=\"delete\" data-id=\"${s.id}\">",
  "            <svg viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"1.7\"><path d=\"M3 6h18M8 6V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2m3 0-1 14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2L4 6\"/></svg>",
  "          </button>",
  "        </div>",
  "      </td>",
  "    `;",
  "    tbody.appendChild(tr);",
  "  });",
  "}",
  "",
  "document.querySelector('#sellerTable').addEventListener('click', (e)=>{",
  "  const btn = e.target.closest('.icon-btn');",
  "  if(!btn) return;",
  "  const id = btn.dataset.id;",
  "  const act = btn.dataset.act;",
  "  const s = sellers.find(x=>x.id===id);",
  "  if(!s) return;",
  "",
  "  if(act==='togglepremium'){",
  "    s.accountType = (s.accountType === 'premium') ? 'normal' : 'premium';",
  "    s.notifications = s.notifications || [];",
  "    s.notifications.unshift({",
  "      id:'n'+Date.now()+Math.random().toString(36).slice(2,7),",
  "      message: s.accountType === 'premium'",
  "        ? 'Tài khoản của bạn đã được quản trị viên nâng cấp lên ★ Premium — đã mở khoá tạo key không giới hạn.'",
  "        : 'Tài khoản của bạn đã được quản trị viên chuyển về loại Thường — tạo key không giới hạn đã bị khoá.',",
  "      time:new Date(), read:false",
  "    });",
  "    renderSellersPage();",
  "    if(currentRole==='seller' && currentAccount===s.username) applySellerAccountEffects();",
  "    showToast('Đã cập nhật loại tài khoản: '+s.username+' → '+(s.accountType==='premium'?'Premium':'Thường'));",
  "  } else if(act==='ban'){",
  "    s.banned = true;",
  "    renderSellersPage();",
  "    showToast('Đã cấm tài khoản: '+s.username);",
  "  } else if(act==='unban'){",
  "    s.banned = false;",
  "    renderSellersPage();",
  "    showToast('Đã bỏ cấm tài khoản: '+s.username);",
  "  } else if(act==='delete'){",
  "    if(confirm('Xoá vĩnh viễn tài khoản \"'+s.username+'\"? Kho key của tài khoản này cũng sẽ bị xoá.')){",
  "      sellers = sellers.filter(x=>x.id!==id);",
  "      delete keysStore[s.username];",
  "      renderSellersPage();",
  "      showToast('Đã xoá tài khoản: '+s.username);",
  "    }",
  "  } else if(act==='extend'){",
  "    extendTargetId = id;",
  "    document.getElementById('extendSellerLabel').textContent = 'Tài khoản: ' + s.username + ' — hiện tại: ' + (s.expiresAt ? formatDateTime(s.expiresAt) : 'Không giới hạn');",
  "    document.getElementById('extendAmount').value = 30;",
  "    document.getElementById('extendModalBg').classList.add('show');",
  "  } else if(act==='topup'){",
  "    topupTargetId = id;",
  "    document.getElementById('topupSellerLabel').textContent = 'Tài khoản: ' + s.username + ' — số dư hiện tại: ' + (fmtMoney(s.balance||0) || '0₫');",
  "    document.getElementById('topupAmount').value = '';",
  "    document.getElementById('topupModalBg').classList.add('show');",
  "  } else if(act==='changepass'){",
  "    sellerPassTargetId = id;",
  "    document.getElementById('sellerPassLabel').textContent = 'Tài khoản: ' + s.username;",
  "    document.getElementById('sellerPassNew').value = '';",
  "    document.getElementById('sellerPassModalBg').classList.add('show');",
  "  }",
  "});",
  "",
  "document.getElementById('extendCancel').addEventListener('click', ()=> document.getElementById('extendModalBg').classList.remove('show'));",
  "document.getElementById('extendConfirm').addEventListener('click', ()=>{",
  "  const s = sellers.find(x=>x.id===extendTargetId);",
  "  if(s){",
  "    const amount = Math.max(1, parseFloat(document.getElementById('extendAmount').value) || 1);",
  "    const unit = document.getElementById('extendUnit').value;",
  "    const base = (s.expiresAt && new Date(s.expiresAt) > new Date()) ? new Date(s.expiresAt) : new Date();",
  "    s.expiresAt = computeExpiryFrom(base, amount, unit);",
  "    s.notifications = s.notifications || [];",
  "    s.notifications.unshift({",
  "      id:'n'+Date.now()+Math.random().toString(36).slice(2,7),",
  "      message:`Quản trị viên đã gia hạn tài khoản của bạn. Hạn dùng mới: ${formatDateTime(s.expiresAt)}.`,",
  "      time:new Date(), read:false",
  "    });",
  "    showToast('Đã cộng thêm thời gian cho tài khoản: '+s.username);",
  "    if(currentRole==='seller' && currentAccount===s.username) applySellerAccountEffects();",
  "  }",
  "  document.getElementById('extendModalBg').classList.remove('show');",
  "  renderSellersPage();",
  "});",
  "",
  "document.getElementById('topupCancel').addEventListener('click', ()=> document.getElementById('topupModalBg').classList.remove('show'));",
  "document.getElementById('topupConfirm').addEventListener('click', ()=>{",
  "  const s = sellers.find(x=>x.id===topupTargetId);",
  "  if(s){",
  "    const amount = parseFloat(String(document.getElementById('topupAmount').value).replace(/[^\\d.]/g,'')) || 0;",
  "    if(amount <= 0){ showToast('Vui lòng nhập số tiền hợp lệ'); return; }",
  "    s.balance = (s.balance||0) + amount;",
  "    s.notifications = s.notifications || [];",
  "    s.notifications.unshift({",
  "      id:'n'+Date.now()+Math.random().toString(36).slice(2,7),",
  "      message:`Quản trị viên đã cộng ${fmtMoney(amount)} vào tài khoản của bạn. Số dư hiện tại: ${fmtMoney(s.balance)}.`,",
  "      time:new Date(), read:false",
  "    });",
  "    showToast('Đã cộng '+fmtMoney(amount)+' vào tài khoản: '+s.username);",
  "    document.getElementById('topupModalBg').classList.remove('show');",
  "    renderSellersPage();",
  "    if(currentRole==='seller' && currentAccount===s.username) applySellerAccountEffects();",
  "  } else {",
  "    document.getElementById('topupModalBg').classList.remove('show');",
  "  }",
  "});",
  "",
  "document.getElementById('sellerPassCancel').addEventListener('click', ()=> document.getElementById('sellerPassModalBg').classList.remove('show'));",
  "document.getElementById('sellerPassConfirm').addEventListener('click', ()=>{",
  "  const s = sellers.find(x=>x.id===sellerPassTargetId);",
  "  if(s){",
  "    const next = document.getElementById('sellerPassNew').value.trim();",
  "    if(!next){ showToast('Vui lòng nhập mật khẩu mới'); return; }",
  "    s.password = next;",
  "    showToast('Đã đổi mật khẩu cho tài khoản: '+s.username);",
  "  }",
  "  document.getElementById('sellerPassModalBg').classList.remove('show');",
  "  renderSellersPage();",
  "});",
  "",
  "document.getElementById('btnMarkAllRead').addEventListener('click', ()=>{",
  "  if(currentRole !== 'seller') return;",
  "  const s = sellers.find(x=>x.username===currentAccount);",
  "  if(s && s.notifications) s.notifications.forEach(n=> n.read = true);",
  "  renderNotifPanel();",
  "  showToast('Đã đánh dấu tất cả thông báo là đã đọc');",
  "});",
  "",
  "/* ============ TRANG \"NGƯỜI DÙNG\" (TÀI KHOẢN KHÁCH HÀNG ĐĂNG KÝ Ở TRANG BÁN HÀNG) — ADMIN ONLY ============",
  "   Khác với \"Người bán\" (sellers, quản lý client-side ở trên), đây là tài khoản khách hàng THẬT",
  "   được lưu ở server qua /api/auth/register (storefront) — nên trang này luôn gọi API để lấy dữ liệu",
  "   mới nhất thay vì đọc từ biến state cục bộ. ---- */",
  "let customersCache = [];",
  "let customerTopupTargetId = null;",
  "let customerPassTargetId = null;",
  "",
  "async function loadAndRenderCustomersPage(){",
  "  try{",
  "    const res = await fetch(API_BASE + '/api/admin/customers', { cache:'no-store' });",
  "    customersCache = await res.json();",
  "  }catch(e){",
  "    console.warn('[KeyVault] Không tải được danh sách người dùng', e);",
  "    customersCache = [];",
  "  }",
  "  renderCustomersTable();",
  "  await loadAndRenderTopupRequests();",
  "}",
  "",
  "function renderCustomersTable(){",
  "  const tbody = document.querySelector('#customerTable tbody');",
  "  tbody.innerHTML = '';",
  "  document.getElementById('customerEmptyState').style.display = customersCache.length ? 'none' : 'block';",
  "  customersCache.forEach(c=>{",
  "    const tr = document.createElement('tr');",
  "    tr.innerHTML = `",
  "      <td class=\"mono\">${c.username}</td>",
  "      <td><span class=\"badge ${c.role==='admin' ? 'active' : ''}\">${c.role==='admin' ? 'Quản trị viên' : 'Khách hàng'}</span></td>",
  "      <td>${formatDateTime(c.createdAt)}</td>",
  "      <td class=\"mono\" style=\"font-size:12px;\">${c.registrationIP || '—'}</td>",
  "      <td class=\"mono stat-balance\">${fmtMoney(c.balance||0) || '0₫'}</td>",
  "      <td>${c.topupCount||0}</td>",
  "      <td>${c.transactionCount||0}</td>",
  "      <td>",
  "        <div class=\"actions\">",
  "          <button class=\"icon-btn\" title=\"Thêm tiền cho tài khoản\" data-act=\"topup\" data-id=\"${c.id}\">",
  "            <svg viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"1.7\"><circle cx=\"12\" cy=\"12\" r=\"9\"/><path d=\"M12 8v8M8 12h8\"/></svg>",
  "          </button>",
  "          <button class=\"icon-btn\" title=\"Đổi mật khẩu\" data-act=\"changepass\" data-id=\"${c.id}\">",
  "            <svg viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"1.7\"><rect x=\"5\" y=\"11\" width=\"14\" height=\"9\" rx=\"2\"/><path d=\"M8 11V7a4 4 0 0 1 8 0v4\"/></svg>",
  "          </button>",
  "        </div>",
  "      </td>",
  "    `;",
  "    tbody.appendChild(tr);",
  "  });",
  "}",
  "",
  "document.querySelector('#customerTable').addEventListener('click', (e)=>{",
  "  const btn = e.target.closest('.icon-btn');",
  "  if(!btn) return;",
  "  const id = btn.dataset.id;",
  "  const act = btn.dataset.act;",
  "  const c = customersCache.find(x=>x.id===id);",
  "  if(!c) return;",
  "",
  "  if(act==='topup'){",
  "    customerTopupTargetId = id;",
  "    document.getElementById('customerTopupLabel').textContent = 'Tài khoản: ' + c.username + ' · Số dư hiện tại: ' + (fmtMoney(c.balance||0)||'0₫');",
  "    document.getElementById('customerTopupAmount').value = '';",
  "    document.getElementById('customerTopupModalBg').classList.add('show');",
  "  } else if(act==='changepass'){",
  "    customerPassTargetId = id;",
  "    document.getElementById('customerPassLabel').textContent = 'Tài khoản: ' + c.username;",
  "    document.getElementById('customerPassNew').value = '';",
  "    document.getElementById('customerPassModalBg').classList.add('show');",
  "  }",
  "});",
  "",
  "document.getElementById('customerTopupCancel').addEventListener('click', ()=> document.getElementById('customerTopupModalBg').classList.remove('show'));",
  "document.getElementById('customerTopupConfirm').addEventListener('click', async ()=>{",
  "  const c = customersCache.find(x=>x.id===customerTopupTargetId);",
  "  if(!c) { document.getElementById('customerTopupModalBg').classList.remove('show'); return; }",
  "  const amount = parseFloat(document.getElementById('customerTopupAmount').value.replace(/[^\\d.-]/g,'')) || 0;",
  "  if(amount === 0){ showToast('Vui lòng nhập số tiền hợp lệ'); return; }",
  "  try{",
  "    const res = await fetch(`${API_BASE}/api/admin/customers/${c.id}/balance`, {",
  "      method:'POST', headers:{'Content-Type':'application/json'},",
  "      body: JSON.stringify({ amount, note: 'Admin cộng tiền thủ công' })",
  "    });",
  "    const data = await res.json();",
  "    if(!res.ok || !data.ok) throw new Error('Cộng tiền thất bại');",
  "    showToast('Đã cộng '+fmtMoney(amount)+' vào tài khoản: '+c.username);",
  "    document.getElementById('customerTopupModalBg').classList.remove('show');",
  "    loadAndRenderCustomersPage();",
  "  }catch(e){",
  "    showToast('Có lỗi xảy ra — kiểm tra kết nối tới server backend');",
  "  }",
  "});",
  "",
  "document.getElementById('customerPassCancel').addEventListener('click', ()=> document.getElementById('customerPassModalBg').classList.remove('show'));",
  "document.getElementById('customerPassConfirm').addEventListener('click', async ()=>{",
  "  const c = customersCache.find(x=>x.id===customerPassTargetId);",
  "  if(!c) { document.getElementById('customerPassModalBg').classList.remove('show'); return; }",
  "  const next = document.getElementById('customerPassNew').value.trim();",
  "  if(next.length < 4){ showToast('Mật khẩu cần tối thiểu 4 ký tự'); return; }",
  "  try{",
  "    const res = await fetch(`${API_BASE}/api/admin/customers/${c.id}/password`, {",
  "      method:'POST', headers:{'Content-Type':'application/json'},",
  "      body: JSON.stringify({ newPassword: next })",
  "    });",
  "    const data = await res.json();",
  "    if(!res.ok || !data.ok) throw new Error('Đổi mật khẩu thất bại');",
  "    showToast('Đã đổi mật khẩu cho tài khoản: '+c.username);",
  "    document.getElementById('customerPassModalBg').classList.remove('show');",
  "  }catch(e){",
  "    showToast('Có lỗi xảy ra — kiểm tra kết nối tới server backend');",
  "  }",
  "});",
  "",
  "document.getElementById('btnRefreshCustomers').addEventListener('click', loadAndRenderCustomersPage);",
  "",
  "const TOPUP_STATUS_LABEL = { pending:'Đang chờ duyệt', approved:'Đã duyệt', rejected:'Đã từ chối' };",
  "const TOPUP_STATUS_CLASS = { pending:'', approved:'active', rejected:'banned' };",
  "async function loadAndRenderTopupRequests(){",
  "  let requests = [];",
  "  try{",
  "    const res = await fetch(API_BASE + '/api/admin/topup-requests', { cache:'no-store' });",
  "    requests = await res.json();",
  "  }catch(e){",
  "    console.warn('[KeyVault] Không tải được danh sách yêu cầu nạp tiền', e);",
  "  }",
  "  const tbody = document.querySelector('#topupRequestTable tbody');",
  "  tbody.innerHTML = '';",
  "  const pending = requests.filter(r=>r.status==='pending');",
  "  document.getElementById('topupRequestEmptyState').style.display = pending.length ? 'none' : 'block';",
  "  requests.forEach(r=>{",
  "    const tr = document.createElement('tr');",
  "    tr.innerHTML = `",
  "      <td class=\"mono\">${r.username}</td>",
  "      <td class=\"mono\">${fmtMoney(r.amount)}</td>",
  "      <td>${r.method==='bank_transfer' ? 'Chuyển khoản' : r.method}</td>",
  "      <td>${formatDateTime(r.createdAt)}</td>",
  "      <td><span class=\"badge ${TOPUP_STATUS_CLASS[r.status]||''}\">${TOPUP_STATUS_LABEL[r.status]||r.status}</span></td>",
  "      <td>",
  "        ${r.status==='pending' ? `",
  "        <div class=\"actions\">",
  "          <button class=\"icon-btn\" title=\"Duyệt\" data-act=\"approve\" data-id=\"${r.id}\">",
  "            <svg viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"1.7\"><circle cx=\"12\" cy=\"12\" r=\"9\"/><path d=\"M8 12l3 3 5-6\"/></svg>",
  "          </button>",
  "          <button class=\"icon-btn danger\" title=\"Từ chối\" data-act=\"reject\" data-id=\"${r.id}\">",
  "            <svg viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"1.7\"><circle cx=\"12\" cy=\"12\" r=\"9\"/><path d=\"M5.5 5.5l13 13\"/></svg>",
  "          </button>",
  "        </div>` : '—'}",
  "      </td>",
  "    `;",
  "    tbody.appendChild(tr);",
  "  });",
  "}",
  "",
  "document.querySelector('#topupRequestTable').addEventListener('click', async (e)=>{",
  "  const btn = e.target.closest('.icon-btn');",
  "  if(!btn) return;",
  "  const id = btn.dataset.id;",
  "  const act = btn.dataset.act;",
  "  try{",
  "    const res = await fetch(`${API_BASE}/api/admin/topup-requests/${id}/${act}`, { method:'POST' });",
  "    const data = await res.json();",
  "    if(!res.ok || !data.ok) throw new Error('Thao tác thất bại');",
  "    showToast(act==='approve' ? 'Đã duyệt yêu cầu nạp tiền' : 'Đã từ chối yêu cầu nạp tiền');",
  "    loadAndRenderCustomersPage();",
  "  }catch(e){",
  "    showToast('Có lỗi xảy ra — kiểm tra kết nối tới server backend');",
  "  }",
  "});",
  "",
  "/* ============ CẤU HÌNH NHẬN TIỀN TỰ ĐỘNG (SEPAY) ============ */",
  "function renderSepaySettings(){",
  "  const enabledEl = document.getElementById('sepayEnabledToggle');",
  "  const bankIdEl = document.getElementById('bankIdInput');",
  "  const accNoEl = document.getElementById('bankAccountNoInput');",
  "  const accNameEl = document.getElementById('bankAccountNameInput');",
  "  const apiKeyEl = document.getElementById('sepayApiKeyInput');",
  "  const urlHintEl = document.getElementById('sepayWebhookUrlHint');",
  "  if(!enabledEl) return; // trang chưa render xong DOM, bỏ qua",
  "  enabledEl.checked = !!(sepayConfig && sepayConfig.enabled);",
  "  bankIdEl.value = (bankInfo && bankInfo.bankId) || 'MB';",
  "  accNoEl.value = (bankInfo && bankInfo.accountNo) || '';",
  "  accNameEl.value = (bankInfo && bankInfo.accountName) || '';",
  "  apiKeyEl.value = (sepayConfig && sepayConfig.apiKey) || '';",
  "  if(urlHintEl) urlHintEl.textContent = window.location.origin + '/api/sepay-webhook';",
  "}",
  "",
  "const btnSaveSepayConfigEl = document.getElementById('btnSaveSepayConfig');",
  "if(btnSaveSepayConfigEl){",
  "  btnSaveSepayConfigEl.addEventListener('click', async ()=>{",
  "    const errBox = document.getElementById('sepayConfigError');",
  "    const okBox = document.getElementById('sepayConfigSuccess');",
  "    errBox.style.display = 'none';",
  "    okBox.style.display = 'none';",
  "    const enabled = document.getElementById('sepayEnabledToggle').checked;",
  "    const newBankId = document.getElementById('bankIdInput').value.trim() || 'MB';",
  "    const newAccNo = document.getElementById('bankAccountNoInput').value.trim();",
  "    const newAccName = document.getElementById('bankAccountNameInput').value.trim();",
  "    const newApiKey = document.getElementById('sepayApiKeyInput').value.trim();",
  "    if(enabled && !newApiKey){",
  "      errBox.textContent = 'Cần nhập API Key trước khi bật đối soát tự động.';",
  "      errBox.style.display = 'block';",
  "      return;",
  "    }",
  "    if(!newAccNo || !newAccName){",
  "      errBox.textContent = 'Cần nhập đầy đủ số tài khoản và tên chủ tài khoản.';",
  "      errBox.style.display = 'block';",
  "      return;",
  "    }",
  "    bankInfo = { bankId: newBankId, accountNo: newAccNo, accountName: newAccName };",
  "    sepayConfig = { enabled, apiKey: newApiKey };",
  "    await saveStateToServer(true);",
  "    okBox.textContent = '✔ Đã lưu cấu hình.';",
  "    okBox.style.display = 'block';",
  "    setTimeout(()=>{ okBox.style.display = 'none'; }, 3000);",
  "  });",
  "}",
  "",
  "/* ============ KEY MANAGEMENT LOGIC ============ */",
  "let keys = []; // {id, value, type, status, banned, customer, price, deviceId, createdAt, expiresAt} — tham chiếu tới keysStore[currentAccount]",
  "let sellTargetId = null;",
  "",
  "function setKeys(newArr){",
  "  keys = newArr;",
  "  if(currentAccount) keysStore[currentAccount] = keys;",
  "}",
  "",
  "const $ = (id) => document.getElementById(id);",
  "",
  "function genSegment(len, charset){",
  "  let s='';",
  "  for(let i=0;i<len;i++) s += charset[Math.floor(Math.random()*charset.length)];",
  "  return s;",
  "}",
  "",
  "function getCharset(){",
  "  if($('csNoAmbig').checked) return 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';",
  "  if($('csNum').checked) return '0123456789';",
  "  return 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';",
  "}",
  "",
  "function buildFormatPreview(){",
  "  const prefix = $('cfgPrefix').value.trim().toUpperCase();",
  "  const groups = Math.max(1, parseInt($('cfgGroups').value)||1);",
  "  const len = Math.max(2, parseInt($('cfgLen').value)||4);",
  "  const parts = [];",
  "  if(prefix) parts.push(prefix);",
  "  for(let i=0;i<groups;i++) parts.push('X'.repeat(len));",
  "  $('formatPreview').textContent = parts.join('-');",
  "}",
  "['cfgPrefix','cfgGroups','cfgLen'].forEach(id=>$(id).addEventListener('input', buildFormatPreview));",
  "document.querySelectorAll('#charsetToggle input').forEach(el=>el.addEventListener('change', buildFormatPreview));",
  "buildFormatPreview();",
  "",
  "document.querySelectorAll('#expiryToggle input').forEach(el=>{",
  "  el.addEventListener('change', ()=>{",
  "    $('expiryFields').style.display = $('expLimited').checked ? 'block' : 'none';",
  "  });",
  "});",
  "$('expiryFields').style.display = $('expLimited').checked ? 'block' : 'none';",
  "",
  "document.querySelectorAll('#createdAtToggle input').forEach(el=>{",
  "  el.addEventListener('change', ()=>{",
  "    $('createdAtCustomField').style.display = $('createdAtCustom').checked ? 'grid' : 'none';",
  "  });",
  "});",
  "",
  "function formatDateTime(d){",
  "  if(!d) return '—';",
  "  const dt = new Date(d);",
  "  return dt.toLocaleString('vi-VN', {hour:'2-digit', minute:'2-digit', day:'2-digit', month:'2-digit', year:'numeric'});",
  "}",
  "",
  "function formatRemaining(expiresAt){",
  "  if(!expiresAt) return 'Không giới hạn';",
  "  const diff = new Date(expiresAt) - new Date();",
  "  if(diff <= 0) return 'Đã hết hạn';",
  "  const totalMin = Math.floor(diff/60000);",
  "  const days = Math.floor(totalMin/1440);",
  "  const hours = Math.floor((totalMin%1440)/60);",
  "  const mins = totalMin%60;",
  "  const parts = [];",
  "  if(days) parts.push(days+' ngày');",
  "  if(hours) parts.push(hours+' giờ');",
  "  if(!days && mins) parts.push(mins+' phút');",
  "  return 'Còn ' + (parts.join(' ') || '< 1 phút');",
  "}",
  "",
  "function computeStatus(k){",
  "  if(k.banned) return 'banned';",
  "  // Key có hạn dùng nhưng CHƯA được kích hoạt (chưa xác thực lần nào qua /api/verify):",
  "  // chưa tính hết hạn, hiển thị riêng \"Chưa kích hoạt\" thay vì \"Hết hạn\"/\"Còn hàng\".",
  "  if(k.hasExpiryPlan && !k.activated) return 'unactivated';",
  "  if(k.expiresAt && new Date() > new Date(k.expiresAt)) return 'expired';",
  "  return k.status;",
  "}",
  "",
  "const STATUS_LABEL = {available:'Còn hàng', sold:'Đã bán', banned:'Bị cấm', expired:'Hết hạn', unactivated:'Chưa kích hoạt'};",
  "",
  "function generateKeys(){",
  "  const prefix = $('cfgPrefix').value.trim().toUpperCase();",
  "  const groups = Math.max(1, Math.min(8, parseInt($('cfgGroups').value)||1));",
  "  const len = Math.max(2, Math.min(10, parseInt($('cfgLen').value)||4));",
  "  const qty = Math.max(1, Math.min(500, parseInt($('cfgQty').value)||1));",
  "  const maxDevices = Math.max(1, Math.min(20, parseInt($('cfgMaxDevices').value)||1));",
  "  const price = $('cfgPrice').value.trim();",
  "  const charset = getCharset();",
  "  const type = document.querySelector('input[name=ktype]:checked').value;",
  "  const existing = new Set(keys.map(k=>k.value));",
  "",
  "  // Mốc thời gian tạo key: mặc định là hiện tại. Chỉ tài khoản admin mới được",
  "  // tuỳ chỉnh ngày giờ tạo (VD: nhập lại key cũ đã phát hành trước đó).",
  "  let baseCreatedAt = new Date();",
  "  if(currentRole === 'admin' && $('createdAtCustom').checked){",
  "    const raw = $('cfgCreatedAt').value;",
  "    if(raw){",
  "      const parsed = new Date(raw);",
  "      if(!isNaN(parsed.getTime())) baseCreatedAt = parsed;",
  "    }",
  "  }",
  "",
  "  // LƯU Ý: key có thời hạn giờ đây KHÔNG tính hạn dùng (expiresAt) ngay lúc sinh key.",
  "  // Hạn dùng chỉ bắt đầu được tính từ thời điểm key được KÍCH HOẠT (lần đầu xác thực",
  "  // thành công qua /api/verify). Trước khi kích hoạt, key hiển thị trạng thái \"Chưa kích hoạt\".",
  "  // Thời hạn + giá giờ lấy từ bảng CỐ ĐỊNH (FIXED_KEY_PLANS) — không còn tự nhập số lượng/đơn vị.",
  "  let expiresAt = null;",
  "  let hasExpiryPlan = false;",
  "  let expiryAmount = null;",
  "  let expiryUnit = null;",
  "  let selectedPlan = null; // gói cố định đang chọn — null nếu \"Không giới hạn\"",
  "  if($('expLimited').checked){",
  "    selectedPlan = findFixedPlan($('cfgFixedPlan').value) || findFixedPlan('d1');",
  "    hasExpiryPlan = true;",
  "    expiryAmount = selectedPlan.amount;",
  "    expiryUnit = selectedPlan.unit;",
  "  } else {",
  "    selectedPlan = findFixedPlan('unlimited');",
  "  }",
  "",
  "  // ===== Trừ tiền theo tài khoản người bán (không áp dụng cho admin) =====",
  "  // Giá luôn lấy nguyên từ FIXED_KEY_PLANS (không nhân giảm giá/ưu đãi nào) vì đây là",
  "  // bảng giá CỐ ĐỊNH theo yêu cầu quản trị viên — áp dụng như nhau cho Thường và Premium.",
  "  let sellerObj = null;",
  "  let totalCost = 0;",
  "  if(currentRole === 'seller'){",
  "    sellerObj = sellers.find(x=>x.username===currentAccount);",
  "    const isPremium = !!(sellerObj && sellerObj.accountType === 'premium');",
  "",
  "    // Chặn phòng vệ: tài khoản Thường không được tạo key không giới hạn dù UI đã khoá sẵn.",
  "    if(selectedPlan.id === 'unlimited' && !isPremium){",
  "      showToast('Tài khoản Thường không thể tạo key không giới hạn. Vui lòng chọn \"Có thời hạn\" hoặc liên hệ quản trị viên để nâng cấp Premium.');",
  "      return;",
  "    }",
  "",
  "    totalCost = selectedPlan.price * qty;",
  "",
  "    if(totalCost > (sellerObj ? (sellerObj.balance||0) : 0)){",
  "      showToast(`Số dư không đủ. Cần ${fmtMoney(totalCost)} nhưng tài khoản chỉ còn ${fmtMoney((sellerObj&&sellerObj.balance)||0)}.`);",
  "      return;",
  "    }",
  "  }",
  "",
  "  let created = 0;",
  "  let attempts = 0;",
  "  while(created < qty && attempts < qty*20){",
  "    attempts++;",
  "    const parts = [];",
  "    if(prefix) parts.push(prefix);",
  "    for(let i=0;i<groups;i++) parts.push(genSegment(len, charset));",
  "    const value = parts.join('-');",
  "    if(existing.has(value)) continue;",
  "    existing.add(value);",
  "    keys.unshift({",
  "      id: 'k'+Date.now()+Math.random().toString(36).slice(2,7),",
  "      value,",
  "      type,",
  "      status:'available',",
  "      banned:false,",
  "      customer:'',",
  "      price: price || '',",
  "      deviceId: null,",
  "      maxDevices,",
  "      devices: [],",
  "      createdAt: new Date(baseCreatedAt),",
  "      expiresAt,",
  "      hasExpiryPlan,",
  "      expiryAmount,",
  "      expiryUnit,",
  "      activated: false,",
  "      activatedAt: null",
  "    });",
  "    created++;",
  "  }",
  "",
  "  if(currentRole === 'seller' && sellerObj && created > 0){",
  "    // Chỉ trừ đúng phần tương ứng với số key thực sự sinh được (phòng trường hợp trùng key phải bỏ bớt lượt thử).",
  "    // Giá luôn lấy nguyên theo bảng giá CỐ ĐỊNH của gói đã chọn — không áp dụng giảm giá nào.",
  "    const actualCost = selectedPlan.price * created;",
  "    sellerObj.balance = Math.max(0, (sellerObj.balance||0) - actualCost);",
  "    applySellerAccountEffects();",
  "    render();",
  "    showToast(`Đã sinh ${created} key mới — trừ ${fmtMoney(actualCost)} (còn lại ${fmtMoney(sellerObj.balance)})`);",
  "    return;",
  "  }",
  "",
  "  render();",
  "  showToast(`Đã sinh ${created} key mới`);",
  "}",
  "",
  "function fmtMoney(v){",
  "  const n = parseFloat(String(v).replace(/[^\\d.]/g,''));",
  "  if(!n && n!==0) return '';",
  "  return n.toLocaleString('vi-VN')+'₫';",
  "}",
  "",
  "function render(){",
  "  const q = $('search').value.trim().toLowerCase();",
  "  const filterStatus = $('filterStatus').value;",
  "  const filterType = $('filterType').value;",
  "  const roll = $('rollList');",
  "  roll.innerHTML = '';",
  "",
  "  const filtered = keys.filter(k=>{",
  "    const st = computeStatus(k);",
  "    if(filterStatus!=='all' && st!==filterStatus) return false;",
  "    if(filterType!=='all' && k.type!==filterType) return false;",
  "    if(q && !(k.value.toLowerCase().includes(q) || (k.customer||'').toLowerCase().includes(q))) return false;",
  "    return true;",
  "  });",
  "",
  "  $('emptyState').style.display = filtered.length ? 'none' : 'block';",
  "",
  "  filtered.forEach(k=>{",
  "    const st = computeStatus(k);",
  "    const div = document.createElement('div');",
  "    div.className = 'ticket';",
  "",
  "    const metaBits = [];",
  "    metaBits.push('Tạo: <b>'+formatDateTime(k.createdAt)+'</b>');",
  "    if(k.hasExpiryPlan && !k.activated){",
  "      const unitLabel = k.expiryUnit==='hour' ? 'giờ' : k.expiryUnit==='month' ? 'tháng' : 'ngày';",
  "      metaBits.push('HSD: <b>Chưa kích hoạt</b>');",
  "      metaBits.push('<span class=\"active-txt\">Sẽ dùng trong '+(k.expiryAmount||'?')+' '+unitLabel+' kể từ lúc kích hoạt</span>');",
  "    } else {",
  "      metaBits.push('HSD: <b>'+(k.expiresAt ? formatDateTime(k.expiresAt) : 'Không giới hạn')+'</b>');",
  "      const remain = formatRemaining(k.expiresAt);",
  "      metaBits.push('<span class=\"'+(remain==='Đã hết hạn'?'expired-txt':'active-txt')+'\">'+remain+'</span>');",
  "    }",
  "    if(k.status==='sold' && k.customer) metaBits.push('KH: <b>'+k.customer+'</b>');",
  "    if(k.price) metaBits.push('Giá: <b>'+fmtMoney(k.price)+'</b>');",
  "    const devUsed = (k.devices && k.devices.length) || (k.deviceId ? 1 : 0);",
  "    const devMax = k.maxDevices || 1;",
  "    if(devUsed > 0) metaBits.push('Thiết bị: <b>'+devUsed+'/'+devMax+'</b>');",
  "    else metaBits.push('Thiết bị: <b>0/'+devMax+'</b>');",
  "",
  "    let actionsHtml = `",
  "      <button class=\"icon-btn\" title=\"Sao chép\" data-act=\"copy\" data-id=\"${k.id}\">",
  "        <svg viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"1.7\"><rect x=\"9\" y=\"9\" width=\"12\" height=\"12\" rx=\"2\"/><path d=\"M5 15V5a2 2 0 0 1 2-2h10\"/></svg>",
  "      </button>`;",
  "    if(st==='available'){",
  "      actionsHtml += `",
  "      <button class=\"icon-btn\" title=\"Đánh dấu đã bán\" data-act=\"sell\" data-id=\"${k.id}\">",
  "        <svg viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"1.7\"><path d=\"M20 12V7a1 1 0 0 0-1-1h-6l-9 9 8 8 9-9a1 1 0 0 0 0-1Z\"/><circle cx=\"15\" cy=\"9\" r=\"1\"/></svg>",
  "      </button>`;",
  "    }",
  "    actionsHtml += `",
  "      <button class=\"icon-btn\" title=\"Reset key về ban đầu\" data-act=\"reset\" data-id=\"${k.id}\">",
  "        <svg viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"1.7\"><path d=\"M3 12a9 9 0 1 0 3-6.7\"/><path d=\"M3 4v5h5\"/></svg>",
  "      </button>`;",
  "    if(k.deviceId || (k.devices && k.devices.length)){",
  "      actionsHtml += `",
  "      <button class=\"icon-btn\" title=\"Reset thiết bị liên kết\" data-act=\"resetdevice\" data-id=\"${k.id}\">",
  "        <svg viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"1.7\"><rect x=\"5\" y=\"2\" width=\"14\" height=\"20\" rx=\"2\"/><path d=\"M12 18h.01\"/></svg>",
  "      </button>`;",
  "    }",
  "    if(k.banned){",
  "      actionsHtml += `",
  "      <button class=\"icon-btn\" title=\"Bỏ cấm key\" data-act=\"unban\" data-id=\"${k.id}\">",
  "        <svg viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"1.7\"><circle cx=\"12\" cy=\"12\" r=\"9\"/><path d=\"M8 12l3 3 5-6\"/></svg>",
  "      </button>`;",
  "    } else {",
  "      actionsHtml += `",
  "      <button class=\"icon-btn danger\" title=\"Cấm key\" data-act=\"ban\" data-id=\"${k.id}\">",
  "        <svg viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"1.7\"><circle cx=\"12\" cy=\"12\" r=\"9\"/><path d=\"M5.5 5.5l13 13\"/></svg>",
  "      </button>`;",
  "    }",
  "    actionsHtml += `",
  "      <button class=\"icon-btn danger\" title=\"Xoá key vĩnh viễn\" data-act=\"delete\" data-id=\"${k.id}\">",
  "        <svg viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"1.7\"><path d=\"M3 6h18M8 6V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2m3 0-1 14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2L4 6\"/></svg>",
  "      </button>`;",
  "",
  "    div.innerHTML = `",
  "      <div class=\"ticket-top\">",
  "        <div class=\"key\">${k.value}</div>",
  "        <div class=\"ticket-badges\">",
  "          <span class=\"badge ${k.type}\">${k.type==='premium' ? '★ Premium' : 'Thường'}</span>",
  "          <span class=\"badge ${st}\">${STATUS_LABEL[st]}</span>",
  "        </div>",
  "      </div>",
  "      <div class=\"ticket-bottom\">",
  "        <div class=\"meta\">${metaBits.join(' &nbsp;·&nbsp; ')}</div>",
  "        <div class=\"actions\">${actionsHtml}</div>",
  "      </div>",
  "    `;",
  "    roll.appendChild(div);",
  "  });",
  "",
  "  $('statTotal').textContent = keys.length;",
  "  $('statAvail').textContent = keys.filter(k=>computeStatus(k)==='available').length;",
  "  const soldKeys = keys.filter(k=>k.status==='sold' && !k.banned);",
  "  $('statSold').textContent = keys.filter(k=>computeStatus(k)==='sold').length;",
  "  $('statExpired').textContent = keys.filter(k=>computeStatus(k)==='expired').length;",
  "  $('statBanned').textContent = keys.filter(k=>k.banned).length;",
  "  const revenue = soldKeys.reduce((sum,k)=> sum + (parseFloat(String(k.price).replace(/[^\\d.]/g,''))||0), 0);",
  "  $('statRevenue').textContent = revenue.toLocaleString('vi-VN')+'₫';",
  "}",
  "",
  "$('rollList').addEventListener('click', (e)=>{",
  "  const btn = e.target.closest('.icon-btn');",
  "  if(!btn) return;",
  "  const id = btn.dataset.id;",
  "  const act = btn.dataset.act;",
  "  const k = keys.find(x=>x.id===id);",
  "  if(!k) return;",
  "",
  "  if(act==='copy'){",
  "    navigator.clipboard.writeText(k.value);",
  "    showToast('Đã sao chép: '+k.value);",
  "  } else if(act==='sell'){",
  "    sellTargetId = id;",
  "    $('sellCustomer').value='';",
  "    $('sellPrice').value = k.price || $('cfgPrice').value || '';",
  "    $('sellDevice').value = k.deviceId || '';",
  "    $('sellModalBg').classList.add('show');",
  "  } else if(act==='reset'){",
  "    k.status='available'; k.banned=false; k.customer=''; k.deviceId=null; k.devices=[]; k.price='';",
  "    render();",
  "    showToast('Đã reset key về trạng thái ban đầu');",
  "  } else if(act==='resetdevice'){",
  "    k.deviceId = null; k.devices = [];",
  "    render();",
  "    showToast('Đã reset thiết bị liên kết với key');",
  "  } else if(act==='ban'){",
  "    k.banned = true;",
  "    render();",
  "    showToast('Đã cấm key: '+k.value);",
  "  } else if(act==='unban'){",
  "    k.banned = false;",
  "    render();",
  "    showToast('Đã bỏ cấm key: '+k.value);",
  "  } else if(act==='delete'){",
  "    if(confirm('Xoá vĩnh viễn key này khỏi danh sách?')){",
  "      setKeys(keys.filter(x=>x.id!==id));",
  "      render();",
  "      showToast('Đã xoá key');",
  "    }",
  "  }",
  "});",
  "",
  "$('sellCancel').addEventListener('click', ()=> $('sellModalBg').classList.remove('show'));",
  "$('sellConfirm').addEventListener('click', ()=>{",
  "  const k = keys.find(x=>x.id===sellTargetId);",
  "  if(k){",
  "    k.status='sold';",
  "    k.customer = $('sellCustomer').value.trim();",
  "    k.price = $('sellPrice').value.trim();",
  "    k.deviceId = $('sellDevice').value.trim() || null;",
  "  }",
  "  $('sellModalBg').classList.remove('show');",
  "  render();",
  "  showToast('Đã đánh dấu key là đã bán');",
  "});",
  "",
  "$('btnGenerate').addEventListener('click', generateKeys);",
  "$('search').addEventListener('input', render);",
  "$('filterStatus').addEventListener('change', render);",
  "$('filterType').addEventListener('change', render);",
  "",
  "$('btnCopyAvail').addEventListener('click', ()=>{",
  "  const avail = keys.filter(k=>computeStatus(k)==='available').map(k=>k.value).join('\\n');",
  "  if(!avail){ showToast('Không có key còn hàng'); return; }",
  "  navigator.clipboard.writeText(avail);",
  "  showToast('Đã sao chép toàn bộ key còn hàng');",
  "});",
  "",
  "$('btnExport').addEventListener('click', ()=>{",
  "  if(!keys.length){ showToast('Chưa có key để xuất'); return; }",
  "  const rows = [['Key','Loại','Trạng thái','Khách hàng','Giá','Thiết bị','Ngày tạo','Hết hạn']];",
  "  keys.forEach(k=>{",
  "    rows.push([k.value, k.type, STATUS_LABEL[computeStatus(k)], k.customer||'', k.price||'', k.deviceId||'', formatDateTime(k.createdAt), k.expiresAt?formatDateTime(k.expiresAt):'Không giới hạn']);",
  "  });",
  "  const csv = rows.map(r=> r.map(c=>`\"${String(c).replace(/\"/g,'\"\"')}\"`).join(',')).join('\\n');",
  "  const blob = new Blob(['\\uFEFF'+csv], {type:'text/csv;charset=utf-8;'});",
  "  const url = URL.createObjectURL(blob);",
  "  const a = document.createElement('a');",
  "  a.href = url; a.download = 'danh-sach-key.csv';",
  "  a.click();",
  "  URL.revokeObjectURL(url);",
  "  showToast('Đã xuất file CSV');",
  "});",
  "",
  "$('btnClear').addEventListener('click', ()=>{",
  "  if(!keys.length) return;",
  "  if(confirm('Xoá toàn bộ '+keys.length+' key? Hành động này không thể hoàn tác.')){",
  "    setKeys([]);",
  "    render();",
  "    showToast('Đã xoá toàn bộ key');",
  "  }",
  "});",
  "",
  "/* ---- Gia hạn tất cả key (mọi tài khoản, mọi owner trong keysStore) ----",
  "   Cộng thêm thời gian đã chọn vào hạn dùng của TẤT CẢ key đang có kế hoạch hạn dùng:",
  "   - Key ĐÃ kích hoạt: cộng thêm trực tiếp vào expiresAt hiện tại.",
  "   - Key CHƯA kích hoạt: cộng thêm vào expiryAmount (quy đổi cùng đơn vị với expiryUnit",
  "     của key đó) để khi kích hoạt sau này, thời gian cộng thêm vẫn được tính đúng. */",
  "function countKeysWithExpiryPlan(){",
  "  let n = 0;",
  "  Object.keys(keysStore||{}).forEach(owner=>{ (keysStore[owner]||[]).forEach(k=>{ if(k.hasExpiryPlan) n++; }); });",
  "  return n;",
  "}",
  "$('btnOpenExtendAll').addEventListener('click', ()=>{",
  "  const n = countKeysWithExpiryPlan();",
  "  $('extendAllPreviewNote').textContent = n>0",
  "    ? ('Sẽ áp dụng cho '+n+' key đang có thời hạn (gồm cả key chưa kích hoạt) trên toàn hệ thống.')",
  "    : 'Hiện chưa có key nào có thời hạn để gia hạn (key \"Không giới hạn\" sẽ không bị ảnh hưởng).';",
  "  $('extendAllModalBg').classList.add('show');",
  "});",
  "$('extendAllCancel').addEventListener('click', ()=> $('extendAllModalBg').classList.remove('show'));",
  "$('extendAllConfirm').addEventListener('click', ()=>{",
  "  const amount = Math.max(1, parseFloat($('extendAllAmount').value) || 1);",
  "  const unit = $('extendAllUnit').value;",
  "  const msPerUnit = unit==='hour' ? 3600000 : unit==='day' ? 86400000 : 30*86400000;",
  "  const unitLabel = unit==='hour' ? 'giờ' : unit==='month' ? 'tháng' : 'ngày';",
  "",
  "  let affected = 0;",
  "  Object.keys(keysStore||{}).forEach(owner=>{",
  "    (keysStore[owner]||[]).forEach(k=>{",
  "      if(!k.hasExpiryPlan) return; // key \"Không giới hạn\" không có gì để gia hạn",
  "      if(k.activated){",
  "        const base = (k.expiresAt && new Date(k.expiresAt) > new Date()) ? new Date(k.expiresAt) : new Date();",
  "        k.expiresAt = new Date(base.getTime() + amount*msPerUnit);",
  "      } else {",
  "        // Key chưa kích hoạt: quy đổi thời gian cộng thêm về cùng đơn vị đang lưu của key rồi cộng dồn.",
  "        const keyMsPerUnit = k.expiryUnit==='hour' ? 3600000 : k.expiryUnit==='month' ? 30*86400000 : 86400000;",
  "        const addInKeyUnit = (amount*msPerUnit) / keyMsPerUnit;",
  "        k.expiryAmount = (k.expiryAmount || 0) + addInKeyUnit;",
  "      }",
  "      affected++;",
  "    });",
  "  });",
  "",
  "  if(currentAccount && keysStore[currentAccount]) setKeys(keysStore[currentAccount]);",
  "  $('extendAllModalBg').classList.remove('show');",
  "  saveStateToServer(true);",
  "  render();",
  "  showToast(affected>0 ? ('Đã gia hạn thêm '+amount+' '+unitLabel+' cho '+affected+' key') : 'Không có key nào để gia hạn');",
  "});",
  "",
  "let toastTimer;",
  "function showToast(msg){",
  "  const t = $('toast');",
  "  t.textContent = msg;",
  "  t.classList.add('show');",
  "  clearTimeout(toastTimer);",
  "  toastTimer = setTimeout(()=> t.classList.remove('show'), 2200);",
  "}",
  "",
  "/* ============ STATS PAGE ============ */",
  "function renderStatsPage(){",
  "  $('stTotalKeys').textContent = keys.length;",
  "  $('stActiveKeys').textContent = keys.filter(k=>{const s=computeStatus(k); return s==='available'||s==='sold';}).length;",
  "  $('stExpiredKeys').textContent = keys.filter(k=>computeStatus(k)==='expired').length;",
  "  $('stPremiumKeys').textContent = keys.filter(k=>k.type==='premium').length;",
  "  $('stLoginCount').textContent = loginHistory.length;",
  "",
  "  // creation chart: last 7 days",
  "  const days = [];",
  "  for(let i=6;i>=0;i--){",
  "    const d = new Date();",
  "    d.setDate(d.getDate()-i);",
  "    d.setHours(0,0,0,0);",
  "    days.push(d);",
  "  }",
  "  const counts = days.map(d=>{",
  "    const next = new Date(d); next.setDate(next.getDate()+1);",
  "    return keys.filter(k=> new Date(k.createdAt) >= d && new Date(k.createdAt) < next).length;",
  "  });",
  "  const max = Math.max(1, ...counts);",
  "  const chart = $('creationChart');",
  "  chart.innerHTML = '';",
  "  days.forEach((d,i)=>{",
  "    const col = document.createElement('div');",
  "    col.className = 'bar-col';",
  "    const h = Math.round((counts[i]/max)*100);",
  "    col.innerHTML = `<div class=\"bar-val\">${counts[i]}</div><div class=\"bar\" style=\"height:${h}%\"></div><div class=\"bar-label\">${d.toLocaleDateString('vi-VN',{day:'2-digit',month:'2-digit'})}</div>`;",
  "    chart.appendChild(col);",
  "  });",
  "",
  "  // type breakdown",
  "  const total = keys.length || 1;",
  "  const premium = keys.filter(k=>k.type==='premium').length;",
  "  const normal = keys.length - premium;",
  "  const pPct = Math.round((premium/total)*100);",
  "  const nPct = 100 - pPct;",
  "  $('typeBreakdown').innerHTML = `",
  "    <div class=\"type-bar-row\">",
  "      <div class=\"lbl\"><span>★ Premium</span><span>${premium} key (${pPct}%)</span></div>",
  "      <div class=\"type-bar-track\"><div class=\"type-bar-fill\" style=\"width:${pPct}%; background:linear-gradient(90deg,var(--brass-soft),var(--brass));\"></div></div>",
  "    </div>",
  "    <div class=\"type-bar-row\">",
  "      <div class=\"lbl\"><span>Thường</span><span>${normal} key (${nPct}%)</span></div>",
  "      <div class=\"type-bar-track\"><div class=\"type-bar-fill\" style=\"width:${nPct}%; background:var(--muted);\"></div></div>",
  "    </div>",
  "  `;",
  "",
  "  // expiry table",
  "  const tbody = document.querySelector('#expiryTable tbody');",
  "  tbody.innerHTML = '';",
  "  if(!keys.length){",
  "    tbody.innerHTML = '<tr><td colspan=\"5\" style=\"color:var(--muted); text-align:center; padding:24px;\">Chưa có key nào được tạo</td></tr>';",
  "  } else {",
  "    keys.forEach(k=>{",
  "      const st = computeStatus(k);",
  "      const tr = document.createElement('tr');",
  "      tr.innerHTML = `",
  "        <td class=\"mono\">${k.value}</td>",
  "        <td><span class=\"badge ${k.type}\">${k.type==='premium'?'★ Premium':'Thường'}</span></td>",
  "        <td><span class=\"badge ${st}\">${STATUS_LABEL[st]}</span></td>",
  "        <td>${k.expiresAt ? formatDateTime(k.expiresAt) : 'Không giới hạn'}</td>",
  "        <td>${formatRemaining(k.expiresAt)}</td>",
  "      `;",
  "      tbody.appendChild(tr);",
  "    });",
  "  }",
  "",
  "  // login history table",
  "  const ltbody = document.querySelector('#loginTable tbody');",
  "  ltbody.innerHTML = '';",
  "  loginHistory.forEach(h=>{",
  "    const tr = document.createElement('tr');",
  "    tr.innerHTML = `",
  "      <td>${formatDateTime(h.time)}</td>",
  "      <td>${h.user}</td>",
  "      <td><span class=\"pill ${h.success?'ok':'danger'}\">${h.success?'Thành công':'Thất bại'}</span></td>",
  "    `;",
  "    ltbody.appendChild(tr);",
  "  });",
  "}",
  "",
  "/* ============ SECURITY PAGE (dữ liệu thật do admin thao tác, không tự sinh số liệu ảo) ============ */",
  "let blockedIPs = []; // chỉ có phần tử khi admin tự thêm",
  "let lastScanTime = null;",
  "let scanState = {}; // không còn dùng cho UI (checklist thủ công đã bỏ) — giữ lại để tương thích với /api/state cũ",
  "",
  "let autoScanLoadedOnce = false;",
  "function renderSecurityPage(){",
  "  $('secBlockedIP').textContent = blockedIPs.length;",
  "  $('secLastScan').textContent = lastScanTime ? formatDateTime(lastScanTime) : 'Chưa đánh giá';",
  "  if(!autoScanLoadedOnce){ autoScanLoadedOnce = true; runAutoScan(); }",
  "",
  "  const tbody = document.querySelector('#ipTable tbody');",
  "  tbody.innerHTML = '';",
  "  if(!blockedIPs.length){",
  "    tbody.innerHTML = '<tr><td colspan=\"5\" style=\"color:var(--muted); text-align:center; padding:24px;\">Không có IP nào bị chặn</td></tr>';",
  "  } else {",
  "    blockedIPs.forEach((b,idx)=>{",
  "      const tr = document.createElement('tr');",
  "      tr.innerHTML = `",
  "        <td class=\"mono\">${b.ip}</td>",
  "        <td>${b.reason}</td>",
  "        <td>${formatDateTime(b.time)}</td>",
  "        <td><span class=\"pill danger\">Đã chặn</span></td>",
  "        <td><button class=\"btn btn-ghost btn-inline\" data-unblock=\"${idx}\" style=\"padding:6px 12px; font-size:11.5px;\">Bỏ chặn</button></td>",
  "      `;",
  "      tbody.appendChild(tr);",
  "    });",
  "  }",
  "}",
  "",
  "document.querySelector('#ipTable').addEventListener('click', (e)=>{",
  "  const btn = e.target.closest('[data-unblock]');",
  "  if(!btn) return;",
  "  const idx = parseInt(btn.dataset.unblock);",
  "  const ip = blockedIPs[idx]?.ip;",
  "  blockedIPs.splice(idx,1);",
  "  renderSecurityPage();",
  "  showToast('Đã bỏ chặn IP: '+ip);",
  "});",
  "",
  "$('btnRefreshIP').addEventListener('click', ()=>{",
  "  $('blockIpValue').value = '';",
  "  $('blockIpModalBg').classList.add('show');",
  "});",
  "$('blockIpCancel').addEventListener('click', ()=> $('blockIpModalBg').classList.remove('show'));",
  "$('blockIpConfirm').addEventListener('click', ()=>{",
  "  const ip = $('blockIpValue').value.trim();",
  "  if(!ip){ showToast('Vui lòng nhập địa chỉ IP'); return; }",
  "  blockedIPs.unshift({ ip, reason: $('blockIpReason').value, time: new Date() });",
  "  $('blockIpModalBg').classList.remove('show');",
  "  renderSecurityPage();",
  "  showToast('Đã chặn IP: '+ip);",
  "});",
  "",
  "/* ============ CHECKLIST BẢO MẬT TỰ ĐỘNG (gọi API thật /api/admin/security-scan) ============ */",
  "const AUTO_STATUS_LABEL = { ok: 'Đạt', warn: 'Cảnh báo', fail: 'Nguy hiểm' };",
  "",
  "function renderAutoScanResults(result){",
  "  const box = $('autoScanResults');",
  "  const summary = $('autoScanSummary');",
  "  if(!result){",
  "    box.innerHTML = '';",
  "    summary.textContent = 'Chưa quét lần nào — bấm \"Quét ngay\" để bắt đầu.';",
  "    return;",
  "  }",
  "  box.innerHTML = '';",
  "  result.checks.forEach(c=>{",
  "    const item = document.createElement('div');",
  "    item.className = 'scan-item';",
  "    const cls = c.status==='ok' ? 'ok' : c.status==='warn' ? 'warn' : 'danger';",
  "    item.innerHTML = `",
  "      <div>",
  "        <div class=\"name\">${c.name}</div>",
  "        <div class=\"desc\">${c.detail}</div>",
  "      </div>",
  "      <span class=\"badge ${cls}\">${AUTO_STATUS_LABEL[c.status]||c.status}</span>",
  "    `;",
  "    box.appendChild(item);",
  "  });",
  "  const failCount = result.checks.filter(c=>c.status==='fail').length;",
  "  const warnCount = result.checks.filter(c=>c.status==='warn').length;",
  "  const okCount = result.checks.filter(c=>c.status==='ok').length;",
  "  summary.textContent = `Quét lúc ${formatDateTime(new Date(result.scannedAt))} — ${okCount} đạt, ${warnCount} cảnh báo, ${failCount} nguy hiểm.`;",
  "",
  "  // Cập nhật luôn 2 ô thống kê đầu trang (trước đây do checklist thủ công phụ trách, nay auto scan đảm nhiệm).",
  "  lastScanTime = new Date(result.scannedAt);",
  "  $('secStatus').textContent = failCount>0 ? 'Nguy hiểm' : warnCount>0 ? 'Cảnh báo' : 'An toàn';",
  "  $('secLastScan').textContent = formatDateTime(lastScanTime);",
  "}",
  "",
  "async function runAutoScan(){",
  "  const btn = $('btnAutoScan');",
  "  btn.disabled = true; btn.textContent = 'Đang quét...';",
  "  try{",
  "    const res = await fetch(`${API_BASE}/api/admin/security-scan`, { cache:'no-store' });",
  "    const result = await res.json();",
  "    renderAutoScanResults(result);",
  "    showToast('Đã quét bảo mật tự động xong');",
  "  }catch(e){",
  "    showToast('Quét thất bại — kiểm tra kết nối tới server backend');",
  "  }finally{",
  "    btn.disabled = false; btn.textContent = '🔄 Quét ngay';",
  "  }",
  "}",
  "$('btnAutoScan').addEventListener('click', runAutoScan);",
  "",
  "/* Refresh time-sensitive text periodically while app is open */",
  "setInterval(()=>{",
  "  if(currentPage==='keys') render();",
  "  if(currentPage==='stats') renderStatsPage();",
  "  if(currentRole==='seller') applySellerAccountEffects();",
  "}, 30000);",
  "",
  "/* ============================================================",
  "   NÂNG CẤP MỚI (chỉ bổ sung — không sửa code phía trên):",
  "   1) Tự động lưu/tải toàn bộ dữ liệu qua server backend thật",
  "      (repo \"server---proxy\": index.js + package.json) — tải lại",
  "      trang KHÔNG mất dữ liệu.",
  "   2) Trang \"API Key Server\" — hiển thị link xác thực API key",
  "      thật để dán vào app/tool bên ngoài.",
  "   3) Tự động nhận diện app/tool nào đang gọi link xác thực,",
  "      admin bấm Cho phép / Từ chối cho từng app.",
  "   Bắt buộc: deploy backend (index.js) và sửa hằng số API_BASE",
  "   bên dưới thành địa chỉ server đó (xem README.md).",
  "   ============================================================ */",
  "",
  "const API_BASE = ''; // Giao diện và server API giờ đã được gộp chung 1 file index.js, chạy cùng domain nên để trống (dùng đường dẫn tương đối)",
  "",
  "/* ---------- 1) AUTO LƯU / TẢI TOÀN BỘ DỮ LIỆU ---------- */",
  "let stateLoaded = false;",
  "let lastSavedSnapshot = '';",
  "",
  "function collectAppState(){",
  "  return { adminPassword, loginHistory, keysStore, sellers, blockedIPs, scanState, lastScanTime, statsHidden, products, discountCodes, bankInfo, sepayConfig };",
  "}",
  "",
  "function reviveDates(state){",
  "  if(Array.isArray(state.loginHistory)) state.loginHistory.forEach(h=>{ h.time = h.time ? new Date(h.time) : new Date(); });",
  "  if(state.keysStore){",
  "    Object.keys(state.keysStore).forEach(owner=>{",
  "      (state.keysStore[owner]||[]).forEach(k=>{",
  "        k.createdAt = k.createdAt ? new Date(k.createdAt) : new Date();",
  "        k.expiresAt = k.expiresAt ? new Date(k.expiresAt) : null;",
  "        k.activatedAt = k.activatedAt ? new Date(k.activatedAt) : null;",
  "        // Tương thích ngược: key được tạo TRƯỚC khi có tính năng \"kích hoạt\" sẽ không",
  "        // có field hasExpiryPlan -> coi như đã kích hoạt sẵn (giữ nguyên hành vi cũ,",
  "        // không làm treo hạn dùng của các key đã tồn tại từ trước).",
  "        if(typeof k.hasExpiryPlan === 'undefined'){",
  "          k.hasExpiryPlan = !!k.expiresAt;",
  "          k.activated = true;",
  "          k.activatedAt = k.activatedAt || k.createdAt;",
  "        }",
  "      });",
  "    });",
  "  }",
  "  if(Array.isArray(state.sellers)) state.sellers.forEach(s=>{",
  "    s.createdAt = s.createdAt ? new Date(s.createdAt) : new Date();",
  "    s.expiresAt = s.expiresAt ? new Date(s.expiresAt) : null;",
  "    (s.notifications||[]).forEach(n=>{ n.time = n.time ? new Date(n.time) : new Date(); });",
  "  });",
  "  if(Array.isArray(state.blockedIPs)) state.blockedIPs.forEach(b=>{ b.time = b.time ? new Date(b.time) : new Date(); });",
  "  if(Array.isArray(state.discountCodes)) state.discountCodes.forEach(d=>{",
  "    d.expiresAt = d.expiresAt ? new Date(d.expiresAt) : null;",
  "    d.createdAt = d.createdAt ? new Date(d.createdAt) : new Date();",
  "  });",
  "  if(Array.isArray(state.products)) state.products.forEach(p=>{ p.createdAt = p.createdAt ? new Date(p.createdAt) : new Date(); });",
  "  return state;",
  "}",
  "",
  "function applyAppState(s){",
  "  if(!s || typeof s !== 'object') return;",
  "  reviveDates(s);",
  "  if(s.adminPassword) adminPassword = s.adminPassword;",
  "  if(Array.isArray(s.loginHistory)) loginHistory = s.loginHistory;",
  "  if(s.keysStore && typeof s.keysStore==='object') keysStore = s.keysStore;",
  "  if(Array.isArray(s.sellers)) sellers = s.sellers;",
  "  if(Array.isArray(s.blockedIPs)) blockedIPs = s.blockedIPs;",
  "  if(s.scanState && typeof s.scanState==='object') scanState = s.scanState;",
  "  lastScanTime = s.lastScanTime ? new Date(s.lastScanTime) : null;",
  "  if(typeof s.statsHidden === 'boolean') statsHidden = s.statsHidden;",
  "  if(Array.isArray(s.products)) products = s.products;",
  "  if(Array.isArray(s.discountCodes)) discountCodes = s.discountCodes;",
  "  if(s.bankInfo && typeof s.bankInfo==='object') bankInfo = s.bankInfo;",
  "  if(s.sepayConfig && typeof s.sepayConfig==='object') sepayConfig = s.sepayConfig;",
  "  if(typeof renderSepaySettings === 'function') renderSepaySettings();",
  "  if(currentAccount && keysStore[currentAccount]) setKeys(keysStore[currentAccount]);",
  "}",
  "",
  "async function loadStateFromServer(){",
  "  const loginBtn = document.getElementById('btnLogin');",
  "  if(loginBtn){ loginBtn.disabled = true; loginBtn.textContent = 'Đang tải dữ liệu từ server...'; }",
  "  try{",
  "    const res = await fetch(API_BASE + '/api/state', { cache:'no-store' });",
  "    if(!res.ok) throw new Error('HTTP ' + res.status);",
  "    const s = await res.json();",
  "    applyAppState(s);",
  "    lastSavedSnapshot = JSON.stringify(collectAppState());",
  "    const note = document.getElementById('apiConnStatusNote');",
  "    if(note) note.textContent = '✔ Đã kết nối máy chủ backend. Dữ liệu được tự động lưu và khôi phục khi tải lại trang.';",
  "  }catch(e){",
  "    console.warn('[KeyVault] Không kết nối được backend. Hãy deploy repo backend (index.js) rồi sửa API_BASE trong file này thành đúng địa chỉ server.', e);",
  "    const note = document.getElementById('apiConnStatusNote');",
  "    if(note) note.textContent = '⚠ Chưa kết nối được máy chủ backend. Kiểm tra: (1) server (index.js) đã chạy chưa, (2) biến API_BASE trong file này đã sửa đúng địa chỉ server chưa. Dữ liệu sẽ KHÔNG được lưu khi tải lại trang cho tới khi kết nối được. Xem README.md.';",
  "  } finally {",
  "    stateLoaded = true;",
  "    if(loginBtn){ loginBtn.disabled = false; loginBtn.textContent = 'Đăng nhập'; }",
  "    refreshAllVisiblePages();",
  "  }",
  "}",
  "",
  "async function saveStateToServer(force){",
  "  if(!stateLoaded) return;",
  "  const snap = JSON.stringify(collectAppState());",
  "  if(!force && snap === lastSavedSnapshot) return;",
  "  lastSavedSnapshot = snap;",
  "  try{",
  "    await fetch(API_BASE + '/api/state', { method:'POST', headers:{'Content-Type':'application/json'}, body: snap });",
  "  }catch(e){",
  "    console.warn('[KeyVault] Lưu dữ liệu lên server thất bại, sẽ tự thử lại.', e);",
  "    lastSavedSnapshot = ''; // buộc lần chạy tiếp theo thử lưu lại",
  "  }",
  "}",
  "",
  "function refreshAllVisiblePages(){",
  "  if(currentRole) applyRoleVisibility();",
  "  if(currentPage==='keys') render();",
  "  if(currentPage==='stats') renderStatsPage();",
  "  if(currentPage==='security') renderSecurityPage();",
  "  if(currentPage==='sellers') renderSellersPage();",
  "  if(currentPage==='apikey') renderApiKeyPage();",
  "  if(currentPage==='products'){ renderProductsPage(); renderProductGroupsPage(); }",
  "  if(currentPage==='getkey') renderGetKeyPage();",
  "}",
  "",
  "setInterval(()=> saveStateToServer(false), 4000); // tự lưu định kỳ, chỉ gửi khi có thay đổi thật",
  "window.addEventListener('beforeunload', ()=>{",
  "  if(!stateLoaded) return;",
  "  const snap = JSON.stringify(collectAppState());",
  "  if(snap === lastSavedSnapshot) return;",
  "  try{ navigator.sendBeacon(API_BASE + '/api/state', new Blob([snap], {type:'application/json'})); }catch(e){}",
  "});",
  "",
  "loadStateFromServer();",
  "",
  "/* ---------- 2) & 3) TRANG \"API KEY SERVER\" ---------- */",
  "let apiApps = [];",
  "let apiLogs = [];",
  "",
  "function setupApiKeyLinks(){",
  "  const origin = API_BASE; // backend nằm ở domain riêng (repo \"server---proxy\"), dùng thẳng API_BASE làm gốc",
  "  const verifyUrl = origin + '/api/verify';",
  "  document.getElementById('apiVerifyLink').value = verifyUrl;",
  "  const appId = (document.getElementById('apiAppIdInput').value || 'my-app-01').trim() || 'my-app-01';",
  "  document.getElementById('apiVerifyExample').value = `${verifyUrl}?key=KEY_CUA_KHACH_HANG&app=${encodeURIComponent(appId)}`;",
  "  document.getElementById('apiCodeSample').textContent =",
  "`// Dán đoạn này vào code xác thực key của app/tool bạn",
  "const res = await fetch(\"${verifyUrl}?key=\" + userKey + \"&app=${appId}\");",
  "const data = await res.json();",
  "",
  "if (data.valid) {",
  "  // Key hợp lệ VÀ app/tool này đã được admin cho phép -> chạy tiếp",
  "} else {",
  "  // data.reason: \"key_not_found\" | \"app_pending_approval\" | \"app_denied\" | \"missing_key\"",
  "  // Key sai, hết hạn/bị cấm, hoặc app chưa được cấp phép -> chặn sử dụng",
  "  console.log(data.reason);",
  "}`;",
  "}",
  "",
  "async function fetchApiApps(){",
  "  try{",
  "    const res = await fetch(API_BASE + '/api/apps', {cache:'no-store'});",
  "    apiApps = res.ok ? await res.json() : [];",
  "  }catch(e){ /* giữ nguyên danh sách cũ nếu mất kết nối tạm thời */ }",
  "  renderApiAppsTable();",
  "}",
  "",
  "async function fetchApiLogs(){",
  "  try{",
  "    const res = await fetch(API_BASE + '/api/logs', {cache:'no-store'});",
  "    apiLogs = res.ok ? await res.json() : [];",
  "  }catch(e){ /* giữ nguyên log cũ nếu mất kết nối tạm thời */ }",
  "  renderApiLogsTable();",
  "}",
  "",
  "function renderApiAppsTable(){",
  "  const total = apiApps.length;",
  "  const pending = apiApps.filter(a=>a.status==='pending').length;",
  "  const allowed = apiApps.filter(a=>a.status==='allowed').length;",
  "  const denied = apiApps.filter(a=>a.status==='denied').length;",
  "  document.getElementById('apiTotalApps').textContent = total;",
  "  document.getElementById('apiPendingApps').textContent = pending;",
  "  document.getElementById('apiAllowedApps').textContent = allowed;",
  "  document.getElementById('apiDeniedApps').textContent = denied;",
  "",
  "  const tbody = document.querySelector('#apiAppsTable tbody');",
  "  const empty = document.getElementById('apiAppsEmpty');",
  "  tbody.innerHTML = '';",
  "  empty.style.display = total ? 'none' : '';",
  "  const STATUS_MAP = { allowed:{cls:'available', label:'✔ Cho phép'}, denied:{cls:'banned', label:'✕ Từ chối'}, pending:{cls:'sold', label:'⏳ Chờ duyệt'} };",
  "  apiApps",
  "    .slice()",
  "    .sort((a,b)=> new Date(b.lastUsedAt||b.createdAt) - new Date(a.lastUsedAt||a.createdAt))",
  "    .forEach(a=>{",
  "      const st = STATUS_MAP[a.status] || STATUS_MAP.pending;",
  "      const tr = document.createElement('tr');",
  "      tr.innerHTML = `",
  "        <td class=\"mono\">${a.appId}</td>",
  "        <td><span class=\"badge ${st.cls}\">${st.label}</span></td>",
  "        <td>${a.lastUsedAt ? formatDateTime(new Date(a.lastUsedAt)) : '—'}</td>",
  "        <td>${a.totalChecks||0}</td>",
  "        <td class=\"actions\">",
  "          <button class=\"btn btn-ghost btn-inline\" data-app-action=\"approve\" data-id=\"${a.id}\" style=\"padding:6px 12px; font-size:11.5px;\">Cho phép</button>",
  "          <button class=\"btn btn-danger-ghost btn-inline\" data-app-action=\"deny\" data-id=\"${a.id}\" style=\"padding:6px 12px; font-size:11.5px;\">Từ chối</button>",
  "          <button class=\"icon-btn danger\" data-app-action=\"remove\" data-id=\"${a.id}\" title=\"Xoá ứng dụng\">✕</button>",
  "        </td>",
  "      `;",
  "      tbody.appendChild(tr);",
  "    });",
  "}",
  "",
  "function renderApiLogsTable(){",
  "  const tbody = document.querySelector('#apiLogsTable tbody');",
  "  tbody.innerHTML = '';",
  "  if(!apiLogs.length){",
  "    tbody.innerHTML = '<tr><td colspan=\"4\" style=\"color:var(--muted); text-align:center; padding:24px;\">Chưa có lượt kiểm tra key nào</td></tr>';",
  "    return;",
  "  }",
  "  apiLogs.slice(0,50).forEach(l=>{",
  "    const tr = document.createElement('tr');",
  "    tr.innerHTML = `",
  "      <td>${formatDateTime(new Date(l.time))}</td>",
  "      <td class=\"mono\">${l.appId}</td>",
  "      <td class=\"mono\">${l.key}</td>",
  "      <td><span class=\"pill ${l.valid?'ok':'danger'}\">${l.valid?'Hợp lệ':'Không hợp lệ'}</span></td>",
  "    `;",
  "    tbody.appendChild(tr);",
  "  });",
  "}",
  "",
  "function renderApiKeyPage(){",
  "  setupApiKeyLinks();",
  "  fetchApiApps();",
  "  fetchApiLogs();",
  "}",
  "",
  "document.getElementById('btnGenAppExample').addEventListener('click', setupApiKeyLinks);",
  "document.getElementById('btnRefreshApps').addEventListener('click', ()=>{ fetchApiApps(); fetchApiLogs(); });",
  "",
  "function copyInputValue(inputId){",
  "  const el = document.getElementById(inputId);",
  "  el.select();",
  "  if(navigator.clipboard){",
  "    navigator.clipboard.writeText(el.value).then(()=> showToast('Đã sao chép')).catch(()=> showToast('Không sao chép được, vui lòng copy thủ công'));",
  "  } else {",
  "    showToast('Vui lòng copy thủ công (Ctrl+C)');",
  "  }",
  "}",
  "document.getElementById('btnCopyVerifyLink').addEventListener('click', ()=> copyInputValue('apiVerifyLink'));",
  "document.getElementById('btnCopyVerifyExample').addEventListener('click', ()=> copyInputValue('apiVerifyExample'));",
  "",
  "document.querySelector('#apiAppsTable').addEventListener('click', async (e)=>{",
  "  const btn = e.target.closest('[data-app-action]');",
  "  if(!btn) return;",
  "  const id = btn.dataset.id;",
  "  const action = btn.dataset.appAction;",
  "  try{",
  "    if(action==='approve'){",
  "      await fetch(`${API_BASE}/api/apps/${id}/approve`, {method:'POST'});",
  "      showToast('Đã cho phép ứng dụng dùng server key');",
  "    } else if(action==='deny'){",
  "      await fetch(`${API_BASE}/api/apps/${id}/deny`, {method:'POST'});",
  "      showToast('Đã từ chối ứng dụng');",
  "    } else if(action==='remove'){",
  "      await fetch(`${API_BASE}/api/apps/${id}`, {method:'DELETE'});",
  "      showToast('Đã xoá ứng dụng khỏi danh sách');",
  "    }",
  "  }catch(err){",
  "    showToast('Thao tác thất bại — kiểm tra kết nối tới server backend (API_BASE)');",
  "  }",
  "  fetchApiApps();",
  "});",
  "",
  "// Khi đang mở trang API Key Server, tự động làm mới để nhận diện app mới gọi vào gần như real-time",
  "setInterval(()=>{ if(currentPage==='apikey'){ fetchApiApps(); fetchApiLogs(); } }, 5000);",
  "",
  "/* ============ TRANG SẢN PHẨM (STOREFRONT) & MÃ GIẢM GIÁ ============ */",
  "let editingProductId = null;",
  "let prodLogoDataUrl = '';",
  "",
  "document.getElementById('prodLogoInput').addEventListener('change', (e)=>{",
  "  const file = e.target.files && e.target.files[0];",
  "  if(!file) return;",
  "  const reader = new FileReader();",
  "  reader.onload = ()=>{",
  "    prodLogoDataUrl = reader.result;",
  "    document.getElementById('prodLogoPreview').innerHTML = `<img src=\"${prodLogoDataUrl}\" style=\"width:100%; height:100%; object-fit:cover;\">`;",
  "  };",
  "  reader.readAsDataURL(file);",
  "});",
  "",
  "document.querySelectorAll('#prodDurationToggle input').forEach(el=>{",
  "  el.addEventListener('change', ()=>{",
  "    document.getElementById('prodDurationFields').style.display = document.getElementById('pdurUnlimited').checked ? 'none' : 'grid';",
  "  });",
  "});",
  "",
  "function resetProductForm(){",
  "  editingProductId = null;",
  "  prodLogoDataUrl = '';",
  "  document.getElementById('productFormTitle').textContent = 'Thêm sản phẩm mới';",
  "  document.getElementById('prodName').value = '';",
  "  document.getElementById('prodKeyPrefix').value = '';",
  "  document.getElementById('prodPrice').value = '';",
  "  document.getElementById('prodMaxDevices').value = '1';",
  "  document.getElementById('pdurLimited').checked = true;",
  "  document.getElementById('prodDurationAmount').value = '30';",
  "  document.getElementById('prodDurationUnit').value = 'day';",
  "  document.getElementById('prodDurationFields').style.display = 'grid';",
  "  document.getElementById('prodActive').checked = true;",
  "  document.getElementById('prodLogoInput').value = '';",
  "  document.getElementById('prodLogoPreview').innerHTML = '<svg viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"1.6\" style=\"width:22px; height:22px; color:var(--muted);\"><rect x=\"3\" y=\"3\" width=\"18\" height=\"18\" rx=\"2\"/><circle cx=\"9\" cy=\"9\" r=\"2\"/><path d=\"m21 15-5-5L5 21\"/></svg>';",
  "  document.getElementById('btnCancelEditProduct').style.display = 'none';",
  "}",
  "",
  "document.getElementById('btnCancelEditProduct').addEventListener('click', resetProductForm);",
  "",
  "document.getElementById('btnSaveProduct').addEventListener('click', ()=>{",
  "  const name = document.getElementById('prodName').value.trim();",
  "  const keyPrefix = document.getElementById('prodKeyPrefix').value.trim().toUpperCase();",
  "  const price = document.getElementById('prodPrice').value.trim();",
  "  const maxDevices = Math.max(1, Math.min(20, parseInt(document.getElementById('prodMaxDevices').value)||1));",
  "  const isUnlimited = document.getElementById('pdurUnlimited').checked;",
  "  const durationAmount = isUnlimited ? null : Math.max(1, parseFloat(document.getElementById('prodDurationAmount').value)||1);",
  "  const durationUnit = isUnlimited ? 'unlimited' : document.getElementById('prodDurationUnit').value;",
  "  const active = document.getElementById('prodActive').checked;",
  "",
  "  if(!name){ showToast('Vui lòng nhập tên sản phẩm'); return; }",
  "  if(!keyPrefix){ showToast('Vui lòng nhập tiền tố key liên kết'); return; }",
  "  if(!price){ showToast('Vui lòng nhập giá bán'); return; }",
  "",
  "  if(editingProductId){",
  "    const p = products.find(x=>x.id===editingProductId);",
  "    if(p){",
  "      p.name = name; p.keyPrefix = keyPrefix; p.price = price; p.maxDevices = maxDevices;",
  "      p.durationAmount = durationAmount; p.durationUnit = durationUnit; p.active = active;",
  "      if(prodLogoDataUrl) p.logo = prodLogoDataUrl;",
  "    }",
  "    showToast('Đã cập nhật sản phẩm');",
  "  } else {",
  "    products.unshift({",
  "      id: 'p'+Date.now()+Math.random().toString(36).slice(2,7),",
  "      name, keyPrefix, price, maxDevices,",
  "      durationAmount, durationUnit, active,",
  "      logo: prodLogoDataUrl || '',",
  "      createdAt: new Date()",
  "    });",
  "    showToast('Đã thêm sản phẩm mới — sẽ hiện ngay trên trang bán key');",
  "  }",
  "  resetProductForm();",
  "  saveStateToServer(true);",
  "  renderProductsPage();",
  "});",
  "",
  "function fmtDuration(p){",
  "  if(p.durationUnit==='unlimited' || !p.durationAmount) return 'Không giới hạn';",
  "  const unitLabel = p.durationUnit==='hour' ? 'giờ' : p.durationUnit==='month' ? 'tháng' : 'ngày';",
  "  return p.durationAmount + ' ' + unitLabel;",
  "}",
  "",
  "function renderProductsPage(){",
  "  const list = document.getElementById('productList');",
  "  const empty = document.getElementById('productEmpty');",
  "  list.innerHTML = '';",
  "  empty.style.display = products.length ? 'none' : 'block';",
  "  products.forEach(p=>{",
  "    const stock = Object.values(keysStore).flat().filter(k=> k.value.startsWith(p.keyPrefix+'-') && computeStatus(k)==='available').length;",
  "    const div = document.createElement('div');",
  "    div.className = 'ticket';",
  "    div.innerHTML = `",
  "      <div class=\"ticket-top\">",
  "        <div style=\"display:flex; align-items:center; gap:12px;\">",
  "          <div style=\"width:40px; height:40px; border-radius:10px; overflow:hidden; background:var(--panel-2); border:1px solid var(--line); flex-shrink:0; display:flex; align-items:center; justify-content:center;\">",
  "            ${p.logo ? `<img src=\"${p.logo}\" style=\"width:100%; height:100%; object-fit:cover;\">` : '📦'}",
  "          </div>",
  "          <div class=\"key\" style=\"font-family:'Inter',sans-serif;\">${p.name}</div>",
  "        </div>",
  "        <div class=\"ticket-badges\">",
  "          <span class=\"badge ${p.active ? 'available' : 'expired'}\">${p.active ? 'Đang hiển thị' : 'Đã ẩn'}</span>",
  "        </div>",
  "      </div>",
  "      <div class=\"ticket-bottom\">",
  "        <div class=\"meta\">Prefix: <b>${p.keyPrefix}</b> &nbsp;·&nbsp; Giá: <b>${fmtMoney(p.price)}</b> &nbsp;·&nbsp; Thời hạn: <b>${fmtDuration(p)}</b> &nbsp;·&nbsp; Thiết bị: <b>${p.maxDevices||1}</b> &nbsp;·&nbsp; Còn hàng: <b>${stock}</b></div>",
  "        <div class=\"actions\">",
  "          <button class=\"icon-btn\" title=\"Sửa\" data-act=\"editprod\" data-id=\"${p.id}\">",
  "            <svg viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"1.7\"><path d=\"M12 20h9\"/><path d=\"M16.5 3.5a2.1 2.1 0 0 1 3 3L7 19l-4 1 1-4Z\"/></svg>",
  "          </button>",
  "          <button class=\"icon-btn\" title=\"${p.active ? 'Ẩn khỏi trang bán key' : 'Hiện lên trang bán key'}\" data-act=\"toggleprod\" data-id=\"${p.id}\">",
  "            <svg viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"1.7\"><path d=\"M1 12s4-7 11-7 11 7 11 7-4 7-11 7-11-7-11-7Z\"/><circle cx=\"12\" cy=\"12\" r=\"3\"/></svg>",
  "          </button>",
  "          <button class=\"icon-btn danger\" title=\"Xoá sản phẩm\" data-act=\"delprod\" data-id=\"${p.id}\">",
  "            <svg viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"1.7\"><path d=\"M3 6h18M8 6V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2m3 0-1 14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2L4 6\"/></svg>",
  "          </button>",
  "        </div>",
  "      </div>",
  "    `;",
  "    list.appendChild(div);",
  "  });",
  "  renderDiscountTable();",
  "}",
  "",
  "document.getElementById('productList').addEventListener('click', (e)=>{",
  "  const btn = e.target.closest('.icon-btn');",
  "  if(!btn) return;",
  "  const id = btn.dataset.id;",
  "  const act = btn.dataset.act;",
  "  const p = products.find(x=>x.id===id);",
  "  if(!p) return;",
  "  if(act==='delprod'){",
  "    if(!confirm('Xoá sản phẩm \"'+p.name+'\"? Key trong kho sẽ KHÔNG bị xoá, chỉ gỡ sản phẩm khỏi trang bán key.')) return;",
  "    products = products.filter(x=>x.id!==id);",
  "    showToast('Đã xoá sản phẩm');",
  "  } else if(act==='toggleprod'){",
  "    p.active = !p.active;",
  "    showToast(p.active ? 'Đã hiện sản phẩm lên trang bán key' : 'Đã ẩn sản phẩm khỏi trang bán key');",
  "  } else if(act==='editprod'){",
  "    editingProductId = id;",
  "    prodLogoDataUrl = p.logo || '';",
  "    document.getElementById('productFormTitle').textContent = 'Chỉnh sửa sản phẩm';",
  "    document.getElementById('prodName').value = p.name;",
  "    document.getElementById('prodKeyPrefix').value = p.keyPrefix;",
  "    document.getElementById('prodPrice').value = p.price;",
  "    document.getElementById('prodMaxDevices').value = p.maxDevices || 1;",
  "    if(p.durationUnit==='unlimited'){",
  "      document.getElementById('pdurUnlimited').checked = true;",
  "      document.getElementById('prodDurationFields').style.display = 'none';",
  "    } else {",
  "      document.getElementById('pdurLimited').checked = true;",
  "      document.getElementById('prodDurationFields').style.display = 'grid';",
  "      document.getElementById('prodDurationAmount').value = p.durationAmount || 30;",
  "      document.getElementById('prodDurationUnit').value = p.durationUnit || 'day';",
  "    }",
  "    document.getElementById('prodActive').checked = !!p.active;",
  "    document.getElementById('prodLogoPreview').innerHTML = p.logo ? `<img src=\"${p.logo}\" style=\"width:100%; height:100%; object-fit:cover;\">` : '<svg viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"1.6\" style=\"width:22px; height:22px; color:var(--muted);\"><rect x=\"3\" y=\"3\" width=\"18\" height=\"18\" rx=\"2\"/><circle cx=\"9\" cy=\"9\" r=\"2\"/><path d=\"m21 15-5-5L5 21\"/></svg>';",
  "    document.getElementById('btnCancelEditProduct').style.display = '';",
  "    window.scrollTo({top:0, behavior:'smooth'});",
  "    return;",
  "  }",
  "  saveStateToServer(true);",
  "  renderProductsPage();",
  "});",
  "",
  "/* ---- Mã giảm giá ---- */",
  "document.getElementById('btnAddDiscount').addEventListener('click', ()=>{",
  "  const code = document.getElementById('discCode').value.trim().toUpperCase();",
  "  const percent = Math.max(1, Math.min(99, parseInt(document.getElementById('discPercent').value)||10));",
  "  const maxUses = Math.max(0, parseInt(document.getElementById('discMaxUses').value)||0);",
  "  const expiryRaw = document.getElementById('discExpiry').value;",
  "  const expiresAt = expiryRaw ? new Date(expiryRaw) : null;",
  "",
  "  if(!code){ showToast('Vui lòng nhập mã giảm giá'); return; }",
  "  if(discountCodes.some(d=>d.code===code)){ showToast('Mã giảm giá này đã tồn tại'); return; }",
  "",
  "  discountCodes.unshift({",
  "    id: 'd'+Date.now()+Math.random().toString(36).slice(2,7),",
  "    code, percent, maxUses, usedCount:0, expiresAt, active:true, createdAt: new Date()",
  "  });",
  "  document.getElementById('discCode').value = '';",
  "  document.getElementById('discPercent').value = '10';",
  "  document.getElementById('discMaxUses').value = '0';",
  "  document.getElementById('discExpiry').value = '';",
  "  showToast('Đã tạo mã giảm giá: '+code);",
  "  saveStateToServer(true);",
  "  renderDiscountTable();",
  "});",
  "",
  "function renderDiscountTable(){",
  "  const tbody = document.querySelector('#discountTable tbody');",
  "  const empty = document.getElementById('discountEmpty');",
  "  tbody.innerHTML = '';",
  "  empty.style.display = discountCodes.length ? 'none' : 'block';",
  "  discountCodes.forEach(d=>{",
  "    const expired = d.expiresAt && new Date(d.expiresAt).getTime() < Date.now();",
  "    const usedUp = d.maxUses > 0 && d.usedCount >= d.maxUses;",
  "    const statusLabel = !d.active ? 'Đã tắt' : expired ? 'Hết hạn' : usedUp ? 'Hết lượt' : 'Đang hoạt động';",
  "    const statusClass = !d.active ? 'expired' : expired ? 'expired' : usedUp ? 'expired' : 'available';",
  "    const tr = document.createElement('tr');",
  "    tr.innerHTML = `",
  "      <td><code>${d.code}</code></td>",
  "      <td>${d.percent}%</td>",
  "      <td>${d.usedCount}${d.maxUses>0 ? '/'+d.maxUses : ''}</td>",
  "      <td>${d.expiresAt ? formatDateTime(d.expiresAt) : 'Không giới hạn'}</td>",
  "      <td><span class=\"badge ${statusClass}\">${statusLabel}</span></td>",
  "      <td>",
  "        <button class=\"icon-btn\" title=\"${d.active ? 'Tắt mã' : 'Bật lại mã'}\" data-act=\"toggledisc\" data-id=\"${d.id}\">",
  "          <svg viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"1.7\"><path d=\"M1 12s4-7 11-7 11 7 11 7-4 7-11 7-11-7-11-7Z\"/><circle cx=\"12\" cy=\"12\" r=\"3\"/></svg>",
  "        </button>",
  "        <button class=\"icon-btn danger\" title=\"Xoá mã\" data-act=\"deldisc\" data-id=\"${d.id}\">",
  "          <svg viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"1.7\"><path d=\"M3 6h18M8 6V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2m3 0-1 14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2L4 6\"/></svg>",
  "        </button>",
  "      </td>",
  "    `;",
  "    tbody.appendChild(tr);",
  "  });",
  "}",
  "",
  "document.querySelector('#discountTable').addEventListener('click', (e)=>{",
  "  const btn = e.target.closest('.icon-btn');",
  "  if(!btn) return;",
  "  const id = btn.dataset.id;",
  "  const act = btn.dataset.act;",
  "  const d = discountCodes.find(x=>x.id===id);",
  "  if(!d) return;",
  "  if(act==='deldisc'){",
  "    if(!confirm('Xoá mã giảm giá \"'+d.code+'\"?')) return;",
  "    discountCodes = discountCodes.filter(x=>x.id!==id);",
  "    showToast('Đã xoá mã giảm giá');",
  "  } else if(act==='toggledisc'){",
  "    d.active = !d.active;",
  "    showToast(d.active ? 'Đã bật lại mã' : 'Đã tắt mã');",
  "  }",
  "  saveStateToServer(true);",
  "  renderDiscountTable();",
  "});",
  "",
  "/* ============ NHÓM SẢN PHẨM (1 logo/tên + NHIỀU gói giá) — ADMIN ============ */",
  "let productGroups = [];",
  "let editingPgId = null;",
  "let pgLogoDataUrl = '';",
  "",
  "document.getElementById('pgLogoInput').addEventListener('change', (e)=>{",
  "  const file = e.target.files && e.target.files[0];",
  "  if(!file) return;",
  "  const reader = new FileReader();",
  "  reader.onload = ()=>{",
  "    pgLogoDataUrl = reader.result;",
  "    document.getElementById('pgLogoPreview').innerHTML = `<img src=\"${pgLogoDataUrl}\" style=\"width:100%; height:100%; object-fit:cover;\">`;",
  "  };",
  "  reader.readAsDataURL(file);",
  "});",
  "",
  "let pgPlanDraft = []; // [{id, label, unit, amount, price, keyPrefix, maxDevices}] — bản nháp đang chỉnh trong form",
  "",
  "function renderPgPlanList(){",
  "  const wrap = document.getElementById('pgPlanList');",
  "  wrap.innerHTML = '';",
  "  pgPlanDraft.forEach((d, idx)=>{",
  "    const row = document.createElement('div');",
  "    row.style.cssText = 'display:grid; grid-template-columns:1fr 0.7fr 0.7fr 0.9fr 0.7fr auto; gap:8px; align-items:end; background:var(--panel); border:1px solid var(--line); border-radius:10px; padding:10px;';",
  "    row.innerHTML = `",
  "      <div><label style=\"margin:0 0 4px;\">Nhãn hiển thị</label><input type=\"text\" data-f=\"label\" data-i=\"${idx}\" value=\"${d.label||''}\" placeholder=\"VD: 1 ngày\"></div>",
  "      <div><label style=\"margin:0 0 4px;\">Đơn vị</label><select data-f=\"unit\" data-i=\"${idx}\"><option value=\"hour\" ${d.unit==='hour'?'selected':''}>Giờ</option><option value=\"day\" ${d.unit==='day'?'selected':''}>Ngày</option><option value=\"month\" ${d.unit==='month'?'selected':''}>Tháng</option><option value=\"unlimited\" ${d.unit==='unlimited'?'selected':''}>Không giới hạn</option></select></div>",
  "      <div><label style=\"margin:0 0 4px;\">Số lượng</label><input type=\"number\" min=\"1\" data-f=\"amount\" data-i=\"${idx}\" value=\"${d.amount||1}\" ${d.unit==='unlimited'?'disabled':''}></div>",
  "      <div><label style=\"margin:0 0 4px;\">Giá (₫)</label><input type=\"text\" data-f=\"price\" data-i=\"${idx}\" value=\"${d.price||''}\" placeholder=\"VD: 10000\"></div>",
  "      <div><label style=\"margin:0 0 4px;\">Tiền tố key</label><input type=\"text\" data-f=\"keyPrefix\" data-i=\"${idx}\" value=\"${d.keyPrefix||''}\" placeholder=\"VD: LQ1D\" style=\"text-transform:uppercase;\"></div>",
  "      <button class=\"icon-btn danger\" title=\"Xoá gói này\" data-del=\"${idx}\" style=\"height:38px;\"><svg viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"1.7\"><path d=\"M3 6h18M8 6V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2m3 0-1 14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2L4 6\"/></svg></button>",
  "    `;",
  "    wrap.appendChild(row);",
  "  });",
  "}",
  "",
  "document.getElementById('btnAddPgPlan').addEventListener('click', ()=>{",
  "  pgPlanDraft.push({ id:'', label:'', unit:'day', amount:1, price:'', keyPrefix:'', maxDevices:1 });",
  "  renderPgPlanList();",
  "});",
  "",
  "document.getElementById('pgPlanList').addEventListener('input', (e)=>{",
  "  const f = e.target.dataset.f;",
  "  const i = e.target.dataset.i;",
  "  if(f===undefined || i===undefined) return;",
  "  const item = pgPlanDraft[i];",
  "  if(!item) return;",
  "  if(f==='amount'){ item[f] = Math.max(1, parseInt(e.target.value)||1); }",
  "  else if(f==='keyPrefix'){ item[f] = e.target.value.toUpperCase(); }",
  "  else { item[f] = e.target.value; }",
  "  if(f==='unit'){ renderPgPlanList(); }",
  "});",
  "document.getElementById('pgPlanList').addEventListener('click', (e)=>{",
  "  const btn = e.target.closest('[data-del]');",
  "  if(!btn) return;",
  "  pgPlanDraft.splice(parseInt(btn.dataset.del), 1);",
  "  renderPgPlanList();",
  "});",
  "",
  "function resetPgForm(){",
  "  editingPgId = null;",
  "  pgLogoDataUrl = '';",
  "  pgPlanDraft = [];",
  "  document.getElementById('pgFormTitle').textContent = 'Thêm nhóm sản phẩm mới';",
  "  document.getElementById('pgName').value = '';",
  "  document.getElementById('pgActive').checked = true;",
  "  document.getElementById('pgLogoInput').value = '';",
  "  document.getElementById('pgLogoPreview').innerHTML = '<svg viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"1.6\" style=\"width:22px; height:22px; color:var(--muted);\"><rect x=\"3\" y=\"3\" width=\"18\" height=\"18\" rx=\"2\"/><circle cx=\"9\" cy=\"9\" r=\"2\"/><path d=\"m21 15-5-5L5 21\"/></svg>';",
  "  document.getElementById('btnCancelEditPg').style.display = 'none';",
  "  renderPgPlanList();",
  "}",
  "document.getElementById('btnCancelEditPg').addEventListener('click', resetPgForm);",
  "",
  "async function fetchProductGroups(){",
  "  try{",
  "    const res = await fetch(`${API_BASE}/api/admin/product-groups`, {cache:'no-store'});",
  "    productGroups = await res.json();",
  "  }catch(e){",
  "    console.warn('[KeyVault] Không tải được danh sách nhóm sản phẩm', e);",
  "  }",
  "  renderPgList();",
  "}",
  "",
  "function fmtPgPlanLabel(d){",
  "  if(d.unit==='unlimited') return d.label || 'Không giới hạn';",
  "  const unitLabel = d.unit==='hour' ? 'giờ' : d.unit==='month' ? 'tháng' : 'ngày';",
  "  return d.label || (d.amount + ' ' + unitLabel);",
  "}",
  "",
  "function renderPgList(){",
  "  const list = document.getElementById('pgList');",
  "  const empty = document.getElementById('pgEmpty');",
  "  list.innerHTML = '';",
  "  empty.style.display = productGroups.length ? 'none' : 'block';",
  "  productGroups.forEach(g=>{",
  "    const div = document.createElement('div');",
  "    div.className = 'ticket';",
  "    const plansHtml = (g.plans||[]).map(d=>{",
  "      const stock = Object.values(keysStore).flat().filter(k=> k.value.startsWith(d.keyPrefix+'-') && computeStatus(k)==='available').length;",
  "      return `<div class=\"meta\" style=\"margin-top:4px;\">• ${fmtPgPlanLabel(d)} — <b>${fmtMoney(d.price)}</b> · Prefix: <b>${d.keyPrefix}</b> · Còn hàng: <b>${stock}</b></div>`;",
  "    }).join('');",
  "    div.innerHTML = `",
  "      <div class=\"ticket-top\">",
  "        <div style=\"display:flex; align-items:center; gap:12px;\">",
  "          <div style=\"width:40px; height:40px; border-radius:10px; overflow:hidden; background:var(--panel-2); border:1px solid var(--line); flex-shrink:0; display:flex; align-items:center; justify-content:center;\">",
  "            ${g.logo ? `<img src=\"${g.logo}\" style=\"width:100%; height:100%; object-fit:cover;\">` : '📦'}",
  "          </div>",
  "          <div class=\"key\" style=\"font-family:'Inter',sans-serif;\">${g.name}</div>",
  "        </div>",
  "        <div class=\"ticket-badges\">",
  "          <span class=\"badge ${g.active ? 'available' : 'expired'}\">${g.active ? 'Đang hiển thị' : 'Đã ẩn'}</span>",
  "        </div>",
  "      </div>",
  "      <div class=\"ticket-bottom\">",
  "        <div class=\"meta\">${(g.plans||[]).length} gói giá:</div>",
  "        ${plansHtml}",
  "        <div class=\"actions\" style=\"margin-top:8px;\">",
  "          <button class=\"icon-btn\" title=\"Sửa\" data-act=\"editpg\" data-id=\"${g.id}\">",
  "            <svg viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"1.7\"><path d=\"M12 20h9\"/><path d=\"M16.5 3.5a2.1 2.1 0 0 1 3 3L7 19l-4 1 1-4Z\"/></svg>",
  "          </button>",
  "          <button class=\"icon-btn\" title=\"${g.active ? 'Ẩn khỏi trang bán key' : 'Hiện lên trang bán key'}\" data-act=\"togglepg\" data-id=\"${g.id}\">",
  "            <svg viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"1.7\"><path d=\"M1 12s4-7 11-7 11 7 11 7-4 7-11 7-11-7-11-7Z\"/><circle cx=\"12\" cy=\"12\" r=\"3\"/></svg>",
  "          </button>",
  "          <button class=\"icon-btn danger\" title=\"Xoá nhóm sản phẩm\" data-act=\"delpg\" data-id=\"${g.id}\">",
  "            <svg viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"1.7\"><path d=\"M3 6h18M8 6V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2m3 0-1 14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2L4 6\"/></svg>",
  "          </button>",
  "        </div>",
  "      </div>",
  "    `;",
  "    list.appendChild(div);",
  "  });",
  "}",
  "",
  "document.getElementById('btnSavePg').addEventListener('click', async ()=>{",
  "  const name = document.getElementById('pgName').value.trim();",
  "  const active = document.getElementById('pgActive').checked;",
  "  if(!name){ showToast('Vui lòng nhập tên nhóm sản phẩm'); return; }",
  "  if(!pgPlanDraft.length){ showToast('Vui lòng thêm ít nhất 1 gói giá'); return; }",
  "  for(const d of pgPlanDraft){",
  "    if(!d.keyPrefix){ showToast('Mỗi gói cần có tiền tố key'); return; }",
  "    if(!d.price){ showToast('Mỗi gói cần có giá bán'); return; }",
  "  }",
  "  const payload = {",
  "    id: editingPgId || undefined,",
  "    name, active,",
  "    logo: pgLogoDataUrl || (editingPgId ? undefined : ''),",
  "    plans: pgPlanDraft.map(d=>({ id: d.id || ('plan'+Date.now()+Math.random().toString(36).slice(2,7)), label:d.label, unit:d.unit, amount:d.unit==='unlimited'?null:d.amount, price:d.price, keyPrefix:d.keyPrefix, maxDevices: d.maxDevices||1 }))",
  "  };",
  "  try{",
  "    const res = await fetch(`${API_BASE}/api/admin/product-groups`, {",
  "      method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify(payload)",
  "    });",
  "    if(!res.ok) throw new Error('save_failed');",
  "    showToast(editingPgId ? 'Đã cập nhật nhóm sản phẩm' : 'Đã thêm nhóm sản phẩm mới — sẽ hiện ngay trên trang bán key');",
  "    resetPgForm();",
  "    fetchProductGroups();",
  "  }catch(e){",
  "    showToast('Lưu nhóm sản phẩm thất bại — kiểm tra kết nối tới server backend');",
  "  }",
  "});",
  "",
  "document.getElementById('pgList').addEventListener('click', async (e)=>{",
  "  const btn = e.target.closest('.icon-btn');",
  "  if(!btn) return;",
  "  const id = btn.dataset.id;",
  "  const act = btn.dataset.act;",
  "  const g = productGroups.find(x=>x.id===id);",
  "  if(!g) return;",
  "  try{",
  "    if(act==='delpg'){",
  "      if(!confirm('Xoá nhóm sản phẩm \"'+g.name+'\"? Key trong kho sẽ KHÔNG bị xoá.')) return;",
  "      await fetch(`${API_BASE}/api/admin/product-groups/${id}`, {method:'DELETE'});",
  "      showToast('Đã xoá nhóm sản phẩm');",
  "    } else if(act==='togglepg'){",
  "      await fetch(`${API_BASE}/api/admin/product-groups/${id}/toggle`, {method:'POST'});",
  "      showToast(g.active ? 'Đã ẩn nhóm sản phẩm khỏi trang bán key' : 'Đã hiện nhóm sản phẩm lên trang bán key');",
  "    } else if(act==='editpg'){",
  "      editingPgId = id;",
  "      pgLogoDataUrl = '';",
  "      pgPlanDraft = (g.plans||[]).map(d=>({...d}));",
  "      document.getElementById('pgFormTitle').textContent = 'Chỉnh sửa nhóm sản phẩm';",
  "      document.getElementById('pgName').value = g.name;",
  "      document.getElementById('pgActive').checked = !!g.active;",
  "      document.getElementById('pgLogoPreview').innerHTML = g.logo ? `<img src=\"${g.logo}\" style=\"width:100%; height:100%; object-fit:cover;\">` : '<svg viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"1.6\" style=\"width:22px; height:22px; color:var(--muted);\"><rect x=\"3\" y=\"3\" width=\"18\" height=\"18\" rx=\"2\"/><circle cx=\"9\" cy=\"9\" r=\"2\"/><path d=\"m21 15-5-5L5 21\"/></svg>';",
  "      document.getElementById('btnCancelEditPg').style.display = '';",
  "      renderPgPlanList();",
  "      window.scrollTo({top:0, behavior:'smooth'});",
  "      return;",
  "    }",
  "  }catch(err){",
  "    showToast('Thao tác thất bại — kiểm tra kết nối tới server backend');",
  "  }",
  "  fetchProductGroups();",
  "});",
  "document.getElementById('btnRefreshPg').addEventListener('click', fetchProductGroups);",
  "",
  "function renderProductGroupsPage(){",
  "  renderPgPlanList();",
  "  fetchProductGroups();",
  "}",
  "",
  "/* ============ TRANG GETKEY (VƯỢT LINK NHẬN KEY) — ADMIN ============ */",
  "let getKeyGames = [];",
  "let editingGetKeyGameId = null;",
  "let gkLogoDataUrl = '';",
  "",
  "document.getElementById('gkLogoInput').addEventListener('change', (e)=>{",
  "  const file = e.target.files && e.target.files[0];",
  "  if(!file) return;",
  "  const reader = new FileReader();",
  "  reader.onload = ()=>{",
  "    gkLogoDataUrl = reader.result;",
  "    document.getElementById('gkLogoPreview').innerHTML = `<img src=\"${gkLogoDataUrl}\" style=\"width:100%; height:100%; object-fit:cover;\">`;",
  "  };",
  "  reader.readAsDataURL(file);",
  "});",
  "",
  "let gkDurationDraft = []; // [{id, label, unit, amount, rounds}] — bản nháp đang chỉnh trong form",
  "",
  "function renderGkDurationList(){",
  "  const wrap = document.getElementById('gkDurationList');",
  "  wrap.innerHTML = '';",
  "  gkDurationDraft.forEach((d, idx)=>{",
  "    const row = document.createElement('div');",
  "    row.style.cssText = 'display:grid; grid-template-columns:1.2fr 0.8fr 0.8fr 0.8fr auto; gap:8px; align-items:end; background:var(--panel-2); border:1px solid var(--line); border-radius:10px; padding:10px;';",
  "    row.innerHTML = `",
  "      <div><label style=\"margin:0 0 4px;\">Nhãn hiển thị</label><input type=\"text\" data-f=\"label\" data-i=\"${idx}\" value=\"${d.label||''}\" placeholder=\"VD: 12 giờ\"></div>",
  "      <div><label style=\"margin:0 0 4px;\">Đơn vị</label><select data-f=\"unit\" data-i=\"${idx}\"><option value=\"hour\" ${d.unit==='hour'?'selected':''}>Giờ</option><option value=\"day\" ${d.unit==='day'?'selected':''}>Ngày</option><option value=\"month\" ${d.unit==='month'?'selected':''}>Tháng</option></select></div>",
  "      <div><label style=\"margin:0 0 4px;\">Số lượng</label><input type=\"number\" min=\"1\" data-f=\"amount\" data-i=\"${idx}\" value=\"${d.amount||1}\"></div>",
  "      <div><label style=\"margin:0 0 4px;\">Số lượt vượt link</label><input type=\"number\" min=\"1\" data-f=\"rounds\" data-i=\"${idx}\" value=\"${d.rounds||1}\"></div>",
  "      <button class=\"icon-btn danger\" title=\"Xoá loại này\" data-del=\"${idx}\" style=\"height:38px;\"><svg viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"1.7\"><path d=\"M3 6h18M8 6V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2m3 0-1 14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2L4 6\"/></svg></button>",
  "    `;",
  "    wrap.appendChild(row);",
  "  });",
  "}",
  "",
  "document.getElementById('btnAddGkDuration').addEventListener('click', ()=>{",
  "  gkDurationDraft.push({ id:'', label:'', unit:'hour', amount:12, rounds:1 });",
  "  renderGkDurationList();",
  "});",
  "",
  "document.getElementById('gkDurationList').addEventListener('input', (e)=>{",
  "  const f = e.target.dataset.f;",
  "  const i = e.target.dataset.i;",
  "  if(f===undefined || i===undefined) return;",
  "  const item = gkDurationDraft[i];",
  "  if(!item) return;",
  "  if(f==='amount' || f==='rounds'){ item[f] = Math.max(1, parseInt(e.target.value)||1); }",
  "  else { item[f] = e.target.value; }",
  "});",
  "document.getElementById('gkDurationList').addEventListener('click', (e)=>{",
  "  const btn = e.target.closest('[data-del]');",
  "  if(!btn) return;",
  "  gkDurationDraft.splice(parseInt(btn.dataset.del), 1);",
  "  renderGkDurationList();",
  "});",
  "",
  "function resetGetKeyGameForm(){",
  "  editingGetKeyGameId = null;",
  "  gkLogoDataUrl = '';",
  "  gkDurationDraft = [];",
  "  document.getElementById('getKeyFormTitle').textContent = 'Thêm game GetKey mới';",
  "  document.getElementById('gkName').value = '';",
  "  document.getElementById('gkKeyPrefix').value = '';",
  "  document.getElementById('gkActive').checked = true;",
  "  document.getElementById('gkLogoInput').value = '';",
  "  document.getElementById('gkLogoPreview').innerHTML = '<svg viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"1.6\" style=\"width:22px; height:22px; color:var(--muted);\"><rect x=\"3\" y=\"3\" width=\"18\" height=\"18\" rx=\"2\"/><circle cx=\"9\" cy=\"9\" r=\"2\"/><path d=\"m21 15-5-5L5 21\"/></svg>';",
  "  document.getElementById('btnCancelEditGetKeyGame').style.display = 'none';",
  "  renderGkDurationList();",
  "}",
  "document.getElementById('btnCancelEditGetKeyGame').addEventListener('click', resetGetKeyGameForm);",
  "",
  "async function fetchGetKeyGames(){",
  "  try{",
  "    const res = await fetch(`${API_BASE}/api/admin/getkey/games`, {cache:'no-store'});",
  "    getKeyGames = await res.json();",
  "  }catch(e){",
  "    console.warn('[KeyVault] Không tải được danh sách game GetKey', e);",
  "    getKeyGames = [];",
  "  }",
  "  renderGetKeyGameList();",
  "}",
  "",
  "function fmtGkDuration(d){",
  "  const unitLabel = d.unit==='hour' ? 'giờ' : d.unit==='month' ? 'tháng' : 'ngày';",
  "  return (d.label || (d.amount+' '+unitLabel));",
  "}",
  "",
  "function renderGetKeyGameList(){",
  "  const list = document.getElementById('getKeyGameList');",
  "  const empty = document.getElementById('getKeyGameEmpty');",
  "  list.innerHTML = '';",
  "  empty.style.display = getKeyGames.length ? 'none' : 'block';",
  "  getKeyGames.forEach(g=>{",
  "    const stock = Object.values(keysStore).flat().filter(k=> k.value.startsWith(g.keyPrefix+'-') && computeStatus(k)==='available').length;",
  "    const durationsTxt = (g.durations||[]).map(d=>`${fmtGkDuration(d)} (${d.rounds} lượt)`).join(' · ') || 'Chưa có loại thời hạn';",
  "    const div = document.createElement('div');",
  "    div.className = 'ticket';",
  "    div.innerHTML = `",
  "      <div class=\"ticket-top\">",
  "        <div style=\"display:flex; align-items:center; gap:12px;\">",
  "          <div style=\"width:40px; height:40px; border-radius:10px; overflow:hidden; background:var(--panel-2); border:1px solid var(--line); flex-shrink:0; display:flex; align-items:center; justify-content:center;\">",
  "            ${g.logo ? `<img src=\"${g.logo}\" style=\"width:100%; height:100%; object-fit:cover;\">` : '🎮'}",
  "          </div>",
  "          <div class=\"key\" style=\"font-family:'Inter',sans-serif;\">${g.name}</div>",
  "        </div>",
  "        <div class=\"ticket-badges\">",
  "          <span class=\"badge ${g.active ? 'available' : 'expired'}\">${g.active ? 'Đang hiển thị' : 'Đã ẩn'}</span>",
  "        </div>",
  "      </div>",
  "      <div class=\"ticket-bottom\">",
  "        <div class=\"meta\">Prefix: <b>${g.keyPrefix}</b> &nbsp;·&nbsp; Còn hàng: <b>${stock}</b><br>${durationsTxt}</div>",
  "        <div class=\"actions\">",
  "          <button class=\"icon-btn\" title=\"Sửa\" data-act=\"editgk\" data-id=\"${g.id}\">",
  "            <svg viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"1.7\"><path d=\"M12 20h9\"/><path d=\"M16.5 3.5a2.1 2.1 0 0 1 3 3L7 19l-4 1 1-4Z\"/></svg>",
  "          </button>",
  "          <button class=\"icon-btn\" title=\"${g.active ? 'Ẩn khỏi trang GetKey' : 'Hiện lên trang GetKey'}\" data-act=\"togglegk\" data-id=\"${g.id}\">",
  "            <svg viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"1.7\"><path d=\"M1 12s4-7 11-7 11 7 11 7-4 7-11 7-11-7-11-7Z\"/><circle cx=\"12\" cy=\"12\" r=\"3\"/></svg>",
  "          </button>",
  "          <button class=\"icon-btn danger\" title=\"Xoá game\" data-act=\"delgk\" data-id=\"${g.id}\">",
  "            <svg viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"1.7\"><path d=\"M3 6h18M8 6V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2m3 0-1 14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2L4 6\"/></svg>",
  "          </button>",
  "        </div>",
  "      </div>",
  "    `;",
  "    list.appendChild(div);",
  "  });",
  "}",
  "",
  "document.getElementById('btnSaveGetKeyGame').addEventListener('click', async ()=>{",
  "  const name = document.getElementById('gkName').value.trim();",
  "  const keyPrefix = document.getElementById('gkKeyPrefix').value.trim().toUpperCase();",
  "  const active = document.getElementById('gkActive').checked;",
  "  if(!name){ showToast('Vui lòng nhập tên game'); return; }",
  "  if(!keyPrefix){ showToast('Vui lòng nhập tiền tố key liên kết'); return; }",
  "  if(!gkDurationDraft.length){ showToast('Vui lòng thêm ít nhất 1 loại thời hạn'); return; }",
  "",
  "  const payload = {",
  "    id: editingGetKeyGameId || undefined,",
  "    name, keyPrefix, active,",
  "    logo: gkLogoDataUrl || undefined,",
  "    durations: gkDurationDraft.map(d=>({ id:d.id||undefined, label:d.label, unit:d.unit, amount:d.amount, rounds:d.rounds }))",
  "  };",
  "  try{",
  "    const res = await fetch(`${API_BASE}/api/admin/getkey/games`, {",
  "      method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify(payload)",
  "    });",
  "    const data = await res.json();",
  "    if(!res.ok || !data.ok) throw new Error('save_failed');",
  "    showToast(editingGetKeyGameId ? 'Đã cập nhật game GetKey' : 'Đã thêm game GetKey mới');",
  "    resetGetKeyGameForm();",
  "    fetchGetKeyGames();",
  "  }catch(e){",
  "    showToast('Lưu game GetKey thất bại — kiểm tra kết nối tới server backend');",
  "  }",
  "});",
  "",
  "document.getElementById('getKeyGameList').addEventListener('click', async (e)=>{",
  "  const btn = e.target.closest('.icon-btn');",
  "  if(!btn) return;",
  "  const id = btn.dataset.id;",
  "  const act = btn.dataset.act;",
  "  const g = getKeyGames.find(x=>x.id===id);",
  "  if(!g) return;",
  "  try{",
  "    if(act==='delgk'){",
  "      if(!confirm('Xoá game \"'+g.name+'\"? Key trong kho sẽ KHÔNG bị xoá.')) return;",
  "      await fetch(`${API_BASE}/api/admin/getkey/games/${id}`, {method:'DELETE'});",
  "      showToast('Đã xoá game GetKey');",
  "    } else if(act==='togglegk'){",
  "      await fetch(`${API_BASE}/api/admin/getkey/games/${id}/toggle`, {method:'POST'});",
  "      showToast(g.active ? 'Đã ẩn game khỏi trang GetKey' : 'Đã hiện game lên trang GetKey');",
  "    } else if(act==='editgk'){",
  "      editingGetKeyGameId = id;",
  "      gkLogoDataUrl = g.logo || '';",
  "      gkDurationDraft = (g.durations||[]).map(d=>({ ...d }));",
  "      document.getElementById('getKeyFormTitle').textContent = 'Chỉnh sửa game GetKey';",
  "      document.getElementById('gkName').value = g.name;",
  "      document.getElementById('gkKeyPrefix').value = g.keyPrefix;",
  "      document.getElementById('gkActive').checked = !!g.active;",
  "      document.getElementById('gkLogoPreview').innerHTML = g.logo ? `<img src=\"${g.logo}\" style=\"width:100%; height:100%; object-fit:cover;\">` : '<svg viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"1.6\" style=\"width:22px; height:22px; color:var(--muted);\"><rect x=\"3\" y=\"3\" width=\"18\" height=\"18\" rx=\"2\"/><circle cx=\"9\" cy=\"9\" r=\"2\"/><path d=\"m21 15-5-5L5 21\"/></svg>';",
  "      document.getElementById('btnCancelEditGetKeyGame').style.display = '';",
  "      renderGkDurationList();",
  "      window.scrollTo({top:0, behavior:'smooth'});",
  "      return;",
  "    }",
  "  }catch(e){",
  "    showToast('Thao tác thất bại — kiểm tra kết nối tới server backend');",
  "  }",
  "  fetchGetKeyGames();",
  "});",
  "",
  "document.getElementById('btnRefreshGetKeyGames').addEventListener('click', fetchGetKeyGames);",
  "",
  "function renderGetKeyPage(){",
  "  renderGkDurationList();",
  "  fetchGetKeyGames();",
  "}",
  "</script>",
  "</body>",
  "</html>",
  ""
];
/* ---------------- Trang bán key công khai (storefront), nhúng dạng base64 để tránh xung đột dấu backtick/${} ---------------- */
const STORE_B64_CHUNKS = [
  "PCFET0NUWVBFIGh0bWw+CjxodG1sIGxhbmc9InZpIj4KPGhlYWQ+CjxtZXRhIGNoYXJzZXQ9IlVU",
  "Ri04Ij4KPG1ldGEgbmFtZT0idmlld3BvcnQiIGNvbnRlbnQ9IndpZHRoPWRldmljZS13aWR0aCwg",
  "aW5pdGlhbC1zY2FsZT0xLjAiPgo8dGl0bGU+S2V5VmF1bHQgU3RvcmUg4oCUIE11YSBLZXkgdHLh",
  "u7FjIHR1eeG6v248L3RpdGxlPgo8bGluayByZWw9InByZWNvbm5lY3QiIGhyZWY9Imh0dHBzOi8v",
  "Zm9udHMuZ29vZ2xlYXBpcy5jb20iPgo8bGluayBocmVmPSJodHRwczovL2ZvbnRzLmdvb2dsZWFw",
  "aXMuY29tL2NzczI/ZmFtaWx5PVNwYWNlK0dyb3Rlc2s6d2dodEA1MDA7NjAwOzcwMCZmYW1pbHk9",
  "SW50ZXI6d2dodEA0MDA7NTAwOzYwMDs3MDAmZmFtaWx5PUpldEJyYWlucytNb25vOndnaHRANTAw",
  "OzYwMDs3MDAmZGlzcGxheT1zd2FwIiByZWw9InN0eWxlc2hlZXQiPgo8c3R5bGU+CiAgOnJvb3R7",
  "CiAgICAtLWluazojRjdGN0Y1OwogICAgLS1wYW5lbDojRkZGRkZGOwogICAgLS1wYW5lbC0yOiNG",
  "QkZCRjk7CiAgICAtLWxpbmU6I0U0RTNERDsKICAgIC0tYnJhc3M6I0FEN0YxRTsKICAgIC0tYnJh",
  "c3Mtc29mdDojQzk5QTJFOwogICAgLS1icmFzcy10aW50OiNGNkVDRDM7CiAgICAtLXRleHQ6IzFD",
  "MUIxODsKICAgIC0tbXV0ZWQ6IzdDN0E3MjsKICAgIC0tb2s6IzFGOEY2MzsKICAgIC0tb2stdGlu",
  "dDojRTRGNUVFOwogICAgLS1kYW5nZXI6I0MyM0I0QjsKICAgIC0tZGFuZ2VyLXRpbnQ6I0ZCRUFF",
  "QzsKICAgIC0tc2hhZG93OiAwIDFweCAycHggcmdiYSgyOCwyNywyNCwwLjA0KSwgMCA4cHggMjRw",
  "eCAtMTJweCByZ2JhKDI4LDI3LDI0LDAuMTApOwogIH0KICAqe2JveC1zaXppbmc6Ym9yZGVyLWJv",
  "eDt9CiAgaHRtbCxib2R5e21hcmdpbjowO3BhZGRpbmc6MDt9CiAgYm9keXsKICAgIGJhY2tncm91",
  "bmQ6CiAgICAgIHJhZGlhbC1ncmFkaWVudCgxMDAwcHggNTAwcHggYXQgODglIC04JSwgI0ZCRjJE",
  "QyAwJSwgdHJhbnNwYXJlbnQgNjAlKSwKICAgICAgdmFyKC0taW5rKTsKICAgIGNvbG9yOnZhcigt",
  "LXRleHQpOwogICAgZm9udC1mYW1pbHk6J0ludGVyJyxzYW5zLXNlcmlmOwogICAgbWluLWhlaWdo",
  "dDoxMDB2aDsKICB9CiAgOjpzZWxlY3Rpb257YmFja2dyb3VuZDp2YXIoLS1icmFzcy10aW50KTsg",
  "Y29sb3I6dmFyKC0tdGV4dCk7fQoKICBoZWFkZXIudG9wewogICAgcGFkZGluZzowIDI0cHg7CiAg",
  "ICBib3JkZXItYm90dG9tOjFweCBzb2xpZCB2YXIoLS1saW5lKTsKICAgIHBvc2l0aW9uOnN0aWNr",
  "eTsgdG9wOjA7IGJhY2tncm91bmQ6cmdiYSgyNTUsMjU1LDI1NSwwLjkyKTsgYmFja2Ryb3AtZmls",
  "dGVyOmJsdXIoMTBweCk7IHotaW5kZXg6MjA7CiAgfQogIC50b3Atcm93ewogICAgbWF4LXdpZHRo",
  "OjEwODBweDsgbWFyZ2luOjAgYXV0bzsKICAgIGRpc3BsYXk6ZmxleDsgYWxpZ24taXRlbXM6Y2Vu",
  "dGVyOyBqdXN0aWZ5LWNvbnRlbnQ6c3BhY2UtYmV0d2VlbjsKICAgIHBhZGRpbmc6MThweCAwOwog",
  "IH0KICAuYnJhbmR7ZGlzcGxheTpmbGV4OyBhbGlnbi1pdGVtczpjZW50ZXI7IGdhcDoxMnB4O30K",
  "ICAuYnJhbmQgLm1hcmt7CiAgICB3aWR0aDozNnB4OyBoZWlnaHQ6MzZweDsgYm9yZGVyLXJhZGl1",
  "czoxMHB4OwogICAgYmFja2dyb3VuZDpsaW5lYXItZ3JhZGllbnQoMTU1ZGVnLCB2YXIoLS1icmFz",
  "cy1zb2Z0KSwgdmFyKC0tYnJhc3MpIDY1JSk7CiAgICBkaXNwbGF5OmZsZXg7IGFsaWduLWl0ZW1z",
  "OmNlbnRlcjsganVzdGlmeS1jb250ZW50OmNlbnRlcjsKICAgIGJveC1zaGFkb3c6MCA0cHggMTRw",
  "eCAtNHB4ICNBRDdGMUU2MDsKICB9CiAgLmJyYW5kIC5tYXJrIHN2Z3t3aWR0aDoxOXB4OyBoZWln",
  "aHQ6MTlweDsgY29sb3I6I2ZmZjt9CiAgLmJyYW5kIGgxe2ZvbnQtZmFtaWx5OidTcGFjZSBHcm90",
  "ZXNrJyxzYW5zLXNlcmlmOyBmb250LXNpemU6MTlweDsgbWFyZ2luOjA7IGxldHRlci1zcGFjaW5n",
  "OjAuMnB4O30KICAuYnJhbmQgLnRhZ3tmb250LXNpemU6MTAuNXB4OyBjb2xvcjp2YXIoLS1tdXRl",
  "ZCk7IGxldHRlci1zcGFjaW5nOjEuNHB4OyB0ZXh0LXRyYW5zZm9ybTp1cHBlcmNhc2U7IG1hcmdp",
  "bi10b3A6MXB4O30KCiAgLnRvcC1hY3Rpb25ze2Rpc3BsYXk6ZmxleDsgYWxpZ24taXRlbXM6Y2Vu",
  "dGVyOyBnYXA6MTBweDt9CiAgLmJ0bnsKICAgIGFwcGVhcmFuY2U6bm9uZTsgYm9yZGVyOm5vbmU7",
  "IGN1cnNvcjpwb2ludGVyOwogICAgYmFja2dyb3VuZDpsaW5lYXItZ3JhZGllbnQoMTU1ZGVnLCB2",
  "YXIoLS1icmFzcy1zb2Z0KSwgdmFyKC0tYnJhc3MpIDcwJSk7CiAgICBjb2xvcjojZmZmOyBmb250",
  "LXdlaWdodDo2MDA7IGZvbnQtc2l6ZToxMy41cHg7CiAgICBwYWRkaW5nOjEwcHggMThweDsgYm9y",
  "ZGVyLXJhZGl1czoxMHB4OwogICAgYm94LXNoYWRvdzowIDRweCAxNHB4IC02cHggI0FEN0YxRTgw",
  "OwogICAgdHJhbnNpdGlvbjp0cmFuc2Zvcm0gLjEycywgYm94LXNoYWRvdyAuMTJzOwogIH0KICAu",
  "YnRuOmhvdmVye3RyYW5zZm9ybTp0cmFuc2xhdGVZKC0xcHgpO30KICAuYnRuLWdob3N0ewogICAg",
  "YmFja2dyb3VuZDp2YXIoLS1wYW5lbCk7IGNvbG9yOnZhcigtLXRleHQpOyBib3JkZXI6MXB4IHNv",
  "bGlkIHZhcigtLWxpbmUpOwogICAgYm94LXNoYWRvdzpub25lOwogIH0KICAuYWNjb3VudC1jaGlw",
  "ewogICAgZGlzcGxheTpmbGV4OyBhbGlnbi1pdGVtczpjZW50ZXI7IGdhcDo4cHg7IGZvbnQtc2l6",
  "ZToxM3B4OyBmb250LXdlaWdodDo2MDA7CiAgICBiYWNrZ3JvdW5kOnZhcigtLWJyYXNzLXRpbnQp",
  "OyBjb2xvcjp2YXIoLS1icmFzcyk7IHBhZGRpbmc6OHB4IDE0cHg7IGJvcmRlci1yYWRpdXM6MTBw",
  "eDsKICB9CiAgLmFjY291bnQtY2hpcCBidXR0b257CiAgICBiYWNrZ3JvdW5kOm5vbmU7IGJvcmRl",
  "cjpub25lOyBjb2xvcjp2YXIoLS1tdXRlZCk7IGN1cnNvcjpwb2ludGVyOyBmb250LXNpemU6MTJw",
  "eDsKICAgIHRleHQtZGVjb3JhdGlvbjp1bmRlcmxpbmU7IHBhZGRpbmc6MDsgZm9udC1mYW1pbHk6",
  "J0ludGVyJyxzYW5zLXNlcmlmOwogIH0KICAuYWRtaW4tbGlua3tmb250LXNpemU6MTJweDsgY29s",
  "b3I6dmFyKC0tbXV0ZWQpOyB0ZXh0LWRlY29yYXRpb246bm9uZTt9CiAgLmFkbWluLWxpbms6aG92",
  "ZXJ7Y29sb3I6dmFyKC0tYnJhc3MpOyB0ZXh0LWRlY29yYXRpb246dW5kZXJsaW5lO30KCiAgLyog",
  "LS0tLSBNZW51IDMgZ+G6oWNoIChoYW1idXJnZXIpICsgZHJvcGRvd24gLS0tLSAqLwogIC5tZW51",
  "LXdyYXB7cG9zaXRpb246cmVsYXRpdmU7fQogIC5oYW1idXJnZXItYnRuewogICAgYXBwZWFyYW5j",
  "ZTpub25lOyBjdXJzb3I6cG9pbnRlcjsgd2lkdGg6MzhweDsgaGVpZ2h0OjM4cHg7IGJvcmRlci1y",
  "YWRpdXM6MTBweDsKICAgIGJhY2tncm91bmQ6dmFyKC0tcGFuZWwpOyBib3JkZXI6MXB4IHNvbGlk",
  "IHZhcigtLWxpbmUpOyBjb2xvcjp2YXIoLS10ZXh0KTsKICAgIGRpc3BsYXk6ZmxleDsgYWxpZ24t",
  "aXRlbXM6Y2VudGVyOyBqdXN0aWZ5LWNvbnRlbnQ6Y2VudGVyOwogIH0KICAuaGFtYnVyZ2VyLWJ0",
  "bjpob3Zlcntib3JkZXItY29sb3I6dmFyKC0tYnJhc3Mtc29mdCk7fQogIC5oYW1idXJnZXItYnRu",
  "IHN2Z3t3aWR0aDoxOHB4OyBoZWlnaHQ6MThweDt9CiAgLmRyb3Bkb3duLW1lbnV7CiAgICBkaXNw",
  "bGF5Om5vbmU7IHBvc2l0aW9uOmFic29sdXRlOyB0b3A6Y2FsYygxMDAlICsgOHB4KTsgcmlnaHQ6",
  "MDsgbWluLXdpZHRoOjI0MHB4OwogICAgYmFja2dyb3VuZDp2YXIoLS1wYW5lbCk7IGJvcmRlcjox",
  "cHggc29saWQgdmFyKC0tbGluZSk7IGJvcmRlci1yYWRpdXM6MTRweDsKICAgIGJveC1zaGFkb3c6",
  "MCAyMHB4IDUwcHggLTIwcHggcmdiYSgwLDAsMCwwLjI4KTsgcGFkZGluZzo4cHg7IHotaW5kZXg6",
  "NjA7CiAgfQogIC5kcm9wZG93bi1tZW51LnNob3d7ZGlzcGxheTpibG9jazt9CiAgLmRyb3Bkb3du",
  "LW1lbnUgLmRkLWl0ZW17CiAgICBkaXNwbGF5OmZsZXg7IGFsaWduLWl0ZW1zOmNlbnRlcjsgZ2Fw",
  "OjEwcHg7IHdpZHRoOjEwMCU7IHRleHQtYWxpZ246bGVmdDsKICAgIHBhZGRpbmc6MTBweCAxMnB4",
  "OyBib3JkZXItcmFkaXVzOjlweDsgYm9yZGVyOm5vbmU7IGJhY2tncm91bmQ6bm9uZTsgY3Vyc29y",
  "OnBvaW50ZXI7CiAgICBmb250LWZhbWlseTonSW50ZXInLHNhbnMtc2VyaWY7IGZvbnQtc2l6ZTox",
  "My41cHg7IGNvbG9yOnZhcigtLXRleHQpOyBmb250LXdlaWdodDo1MDA7CiAgfQogIC5kcm9wZG93",
  "bi1tZW51IC5kZC1pdGVtOmhvdmVye2JhY2tncm91bmQ6dmFyKC0tcGFuZWwtMik7fQogIC5kcm9w",
  "ZG93bi1tZW51IC5kZC1pdGVtIHN2Z3t3aWR0aDoxN3B4OyBoZWlnaHQ6MTdweDsgY29sb3I6dmFy",
  "KC0tYnJhc3MpOyBmbGV4LXNocmluazowO30KICAuZHJvcGRvd24tbWVudSAuZGQtc2Vwe2hlaWdo",
  "dDoxcHg7IGJhY2tncm91bmQ6dmFyKC0tbGluZSk7IG1hcmdpbjo2cHggNHB4O30KICAuZHJvcGRv",
  "d24tbWVudSAuZGQtYWNjb3VudHsKICAgIHBhZGRpbmc6MTBweCAxMnB4IDEycHg7IGZvbnQtc2l6",
  "ZToxMi41cHg7IGNvbG9yOnZhcigtLW11dGVkKTsKICB9CiAgLmRyb3Bkb3duLW1lbnUgLmRkLWFj",
  "Y291bnQgYntjb2xvcjp2YXIoLS10ZXh0KTsgZm9udC1zaXplOjEzLjVweDsgZGlzcGxheTpibG9j",
  "azsgbWFyZ2luLWJvdHRvbToycHg7fQoKICBtYWlue21heC13aWR0aDoxMDgwcHg7IG1hcmdpbjow",
  "IGF1dG87IHBhZGRpbmc6MzZweCAyNHB4IDgwcHg7fQoKICAuaGVyb3t0ZXh0LWFsaWduOmNlbnRl",
  "cjsgbWFyZ2luLWJvdHRvbTozNnB4O30KICAuaGVybyBoMntmb250LWZhbWlseTonU3BhY2UgR3Jv",
  "dGVzaycsc2Fucy1zZXJpZjsgZm9udC1zaXplOjI4cHg7IG1hcmdpbjowIDAgOHB4O30KICAuaGVy",
  "byBwe2NvbG9yOnZhcigtLW11dGVkKTsgZm9udC1zaXplOjE0cHg7IG1hcmdpbjowOyBsaW5lLWhl",
  "aWdodDoxLjY7fQogIC5oZXJvIC5iYWRnZXN7ZGlzcGxheTpmbGV4OyBqdXN0aWZ5LWNvbnRlbnQ6",
  "Y2VudGVyOyBnYXA6MTBweDsgbWFyZ2luLXRvcDoxNnB4OyBmbGV4LXdyYXA6d3JhcDt9CiAgLmhl",
  "cm8gLmJhZGdlewogICAgZm9udC1zaXplOjExLjVweDsgY29sb3I6dmFyKC0tYnJhc3MpOyBiYWNr",
  "Z3JvdW5kOnZhcigtLWJyYXNzLXRpbnQpOwogICAgcGFkZGluZzo2cHggMTJweDsgYm9yZGVyLXJh",
  "ZGl1czoyMHB4OyBmb250LXdlaWdodDo2MDA7CiAgfQoKICAuZ3JpZHsKICAgIGRpc3BsYXk6Z3Jp",
  "ZDsgZ3JpZC10ZW1wbGF0ZS1jb2x1bW5zOnJlcGVhdChhdXRvLWZpbGwsIG1pbm1heCgyNjBweCwg",
  "MWZyKSk7IGdhcDoxOHB4OwogIH0KICAuY2FyZHsKICAgIGJhY2tncm91bmQ6dmFyKC0tcGFuZWwp",
  "OyBib3JkZXI6MXB4IHNvbGlkIHZhcigtLWxpbmUpOyBib3JkZXItcmFkaXVzOjE2cHg7CiAgICBw",
  "YWRkaW5nOjIycHg7IGJveC1zaGFkb3c6dmFyKC0tc2hhZG93KTsKICAgIGRpc3BsYXk6ZmxleDsg",
  "ZmxleC1kaXJlY3Rpb246Y29sdW1uOyBnYXA6MTJweDsKICB9CiAgLmNhcmQgLmxvZ297CiAgICB3",
  "aWR0aDo1MnB4OyBoZWlnaHQ6NTJweDsgYm9yZGVyLXJhZGl1czoxMnB4OyBvdmVyZmxvdzpoaWRk",
  "ZW47CiAgICBiYWNrZ3JvdW5kOnZhcigtLXBhbmVsLTIpOyBib3JkZXI6MXB4IHNvbGlkIHZhcigt",
  "LWxpbmUpOwogICAgZGlzcGxheTpmbGV4OyBhbGlnbi1pdGVtczpjZW50ZXI7IGp1c3RpZnktY29u",
  "dGVudDpjZW50ZXI7IGZvbnQtc2l6ZToyMnB4OwogIH0KICAuY2FyZCAubG9nbyBpbWd7d2lkdGg6",
  "MTAwJTsgaGVpZ2h0OjEwMCU7IG9iamVjdC1maXQ6Y292ZXI7fQogIC5jYXJkIGgze2ZvbnQtZmFt",
  "aWx5OidTcGFjZSBHcm90ZXNrJyxzYW5zLXNlcmlmOyBmb250LXNpemU6MTdweDsgbWFyZ2luOjA7",
  "fQogIC5jYXJkIC5wcmljZXtmb250LWZhbWlseTonSmV0QnJhaW5zIE1vbm8nLG1vbm9zcGFjZTsg",
  "Zm9udC1zaXplOjIwcHg7IGZvbnQtd2VpZ2h0OjcwMDsgY29sb3I6dmFyKC0tYnJhc3MpO30KICAu",
  "Y2FyZCAubWV0YXtmb250LXNpemU6MTIuNXB4OyBjb2xvcjp2YXIoLS1tdXRlZCk7IGRpc3BsYXk6",
  "ZmxleDsgZmxleC1kaXJlY3Rpb246Y29sdW1uOyBnYXA6NHB4O30KICAuY2FyZCAuc3RvY2t7Zm9u",
  "dC1zaXplOjExLjVweDsgZm9udC13ZWlnaHQ6NjAwO30KICAuY2FyZCAuc3RvY2suaW57Y29sb3I6",
  "dmFyKC0tb2spO30KICAuY2FyZCAuc3RvY2sub3V0e2NvbG9yOnZhcigtLWRhbmdlcik7fQogIC5j",
  "YXJkIC5idXktYnRue21hcmdpbi10b3A6NnB4O30KICAuY2FyZCAuYnV5LWJ0bltkaXNhYmxlZF17",
  "b3BhY2l0eTouNDU7IGN1cnNvcjpub3QtYWxsb3dlZDsgYm94LXNoYWRvdzpub25lO30KCiAgLyog",
  "LS0tLSBNb2RhbCBjaOG7jW4gZ8OzaSBo4bujcCBuaOG6pXQgKGTDuW5nIGNodW5nIGNobyBHZXRL",
  "ZXkgJiBz4bqjbiBwaOG6qW0gbXVhIGLhurFuZyB0aeG7gW4pIC0tLS0gKi8KICAudW5pZmllZC1w",
  "bGFuLWhlYWRlcntkaXNwbGF5OmZsZXg7IGFsaWduLWl0ZW1zOmNlbnRlcjsgZ2FwOjE0cHg7IG1h",
  "cmdpbi1ib3R0b206NHB4O30KICAudW5pZmllZC1wbGFuLWhlYWRlciAubG9nb3t3aWR0aDo1MnB4",
  "OyBoZWlnaHQ6NTJweDsgYm9yZGVyLXJhZGl1czoxNHB4OyBvdmVyZmxvdzpoaWRkZW47IGJhY2tn",
  "cm91bmQ6dmFyKC0tcGFuZWwtMik7IGJvcmRlcjoxcHggc29saWQgdmFyKC0tbGluZSk7IGRpc3Bs",
  "YXk6ZmxleDsgYWxpZ24taXRlbXM6Y2VudGVyOyBqdXN0aWZ5LWNvbnRlbnQ6Y2VudGVyOyBmb250",
  "LXNpemU6MjRweDsgZmxleC1zaHJpbms6MDt9CiAgLnVuaWZpZWQtcGxhbi1oZWFkZXIgLmxvZ28g",
  "aW1ne3dpZHRoOjEwMCU7IGhlaWdodDoxMDAlOyBvYmplY3QtZml0OmNvdmVyO30KICAudW5pZmll",
  "ZC1wbGFuLWhlYWRlciBoM3ttYXJnaW46MDsgZm9udC1zaXplOjE4cHg7fQogIC51bmlmaWVkLXBs",
  "YW4taGVhZGVyIC5zdWIye21hcmdpbjoycHggMCAwOyBmb250LXNpemU6MTJweDsgY29sb3I6dmFy",
  "KC0tbXV0ZWQpO30KICAucGxhbi1vcHRpb257CiAgICBkaXNwbGF5OmZsZXg7IGFsaWduLWl0ZW1z",
  "OmNlbnRlcjsgZ2FwOjE0cHg7IHdpZHRoOjEwMCU7IHRleHQtYWxpZ246bGVmdDsKICAgIGJhY2tn",
  "cm91bmQ6dmFyKC0tcGFuZWwtMik7IGJvcmRlcjoxcHggc29saWQgdmFyKC0tbGluZSk7IGJvcmRl",
  "ci1yYWRpdXM6MTRweDsgcGFkZGluZzoxNHB4IDE2cHg7CiAgICBjdXJzb3I6cG9pbnRlcjsgdHJh",
  "bnNpdGlvbjpib3JkZXItY29sb3IgLjEyczsKICB9CiAgLnBsYW4tb3B0aW9uOmhvdmVye2JvcmRl",
  "ci1jb2xvcjp2YXIoLS1icmFzcy1zb2Z0KTt9CiAgLnBsYW4tb3B0aW9uW2Rpc2FibGVkXXtvcGFj",
  "aXR5Oi40NTsgY3Vyc29yOm5vdC1hbGxvd2VkO30KICAucGxhbi1vcHRpb24gLmljb257CiAgICB3",
  "aWR0aDo0NHB4OyBoZWlnaHQ6NDRweDsgYm9yZGVyLXJhZGl1czoxMnB4OyBiYWNrZ3JvdW5kOnZh",
  "cigtLWJyYXNzLXRpbnQpOyBjb2xvcjp2YXIoLS1icmFzcyk7CiAgICBkaXNwbGF5OmZsZXg7IGFs",
  "aWduLWl0ZW1zOmNlbnRlcjsganVzdGlmeS1jb250ZW50OmNlbnRlcjsgZmxleC1zaHJpbms6MDsg",
  "Zm9udC1zaXplOjIwcHg7CiAgfQogIC5wbGFuLW9wdGlvbiAuaW5mb3tmbGV4OjE7IG1pbi13aWR0",
  "aDowO30KICAucGxhbi1vcHRpb24gLmluZm8gLmxibHtmb250LXdlaWdodDo3MDA7IGZvbnQtc2l6",
  "ZToxNC41cHg7fQogIC5wbGFuLW9wdGlvbiAuaW5mbyAuc3ViM3tmb250LXNpemU6MTEuNXB4OyBj",
  "b2xvcjp2YXIoLS1tdXRlZCk7IG1hcmdpbi10b3A6MnB4O30KICAucGxhbi1vcHRpb24gLnJpZ2h0",
  "e3RleHQtYWxpZ246cmlnaHQ7IGZsZXgtc2hyaW5rOjA7fQogIC5wbGFuLW9wdGlvbiAucmlnaHQg",
  "LnByaWNle2ZvbnQtZmFtaWx5OidKZXRCcmFpbnMgTW9ubycsbW9ub3NwYWNlOyBmb250LXdlaWdo",
  "dDo3MDA7IGZvbnQtc2l6ZToxNS41cHg7IGNvbG9yOnZhcigtLWJyYXNzKTt9CiAgLnBsYW4tb3B0",
  "aW9uIC5yaWdodCAudGFne2ZvbnQtc2l6ZToxMC41cHg7IGZvbnQtd2VpZ2h0OjcwMDsgY29sb3I6",
  "I2UwYTgwZjsgbWFyZ2luLXRvcDoycHg7fQogIC5wbGFuLW9wdGlvbi5zZWxlY3RlZHtib3JkZXIt",
  "Y29sb3I6dmFyKC0tYnJhc3MpOyBiYWNrZ3JvdW5kOnZhcigtLWJyYXNzLXRpbnQpO30KCiAgLmVt",
  "cHR5LXN0YXRlewogICAgdGV4dC1hbGlnbjpjZW50ZXI7IHBhZGRpbmc6NjBweCAyMHB4OyBjb2xv",
  "cjp2YXIoLS1tdXRlZCk7CiAgICBib3JkZXI6MXB4IGRhc2hlZCB2YXIoLS1saW5lKTsgYm9yZGVy",
  "LXJhZGl1czoxNnB4OyBiYWNrZ3JvdW5kOnZhcigtLXBhbmVsLTIpOwogIH0KICAuZW1wdHktc3Rh",
  "dGUgLmJpZ3tmb250LXNpemU6MTZweDsgZm9udC13ZWlnaHQ6NjAwOyBjb2xvcjp2YXIoLS10ZXh0",
  "KTsgbWFyZ2luLWJvdHRvbTo2cHg7fQoKICBmb290ZXJ7dGV4dC1hbGlnbjpjZW50ZXI7IHBhZGRp",
  "bmc6MjhweDsgY29sb3I6dmFyKC0tbXV0ZWQpOyBmb250LXNpemU6MTEuNXB4O30KCiAgLyogLS0t",
  "LSBNb2RhbCAtLS0tICovCiAgLm1vZGFsLWJnewogICAgZGlzcGxheTpub25lOyBwb3NpdGlvbjpm",
  "aXhlZDsgaW5zZXQ6MDsgYmFja2dyb3VuZDpyZ2JhKDI4LDI3LDI0LDAuNDUpOwogICAgYWxpZ24t",
  "aXRlbXM6Y2VudGVyOyBqdXN0aWZ5LWNvbnRlbnQ6Y2VudGVyOyB6LWluZGV4OjEwMDsgcGFkZGlu",
  "ZzoyMHB4OwogIH0KICAubW9kYWwtYmcuc2hvd3tkaXNwbGF5OmZsZXg7fQogIC5tb2RhbHsKICAg",
  "IHdpZHRoOjEwMCU7IG1heC13aWR0aDo0MDBweDsgYmFja2dyb3VuZDp2YXIoLS1wYW5lbCk7IGJv",
  "cmRlci1yYWRpdXM6MTZweDsKICAgIHBhZGRpbmc6MjhweCAyNnB4OyBib3gtc2hhZG93OjAgMjBw",
  "eCA2MHB4IC0yMHB4IHJnYmEoMCwwLDAsMC4zNSk7CiAgICBtYXgtaGVpZ2h0Ojkwdmg7IG92ZXJm",
  "bG93LXk6YXV0bzsKICB9CiAgLm1vZGFsIGgze2ZvbnQtZmFtaWx5OidTcGFjZSBHcm90ZXNrJyxz",
  "YW5zLXNlcmlmOyBmb250LXNpemU6MTlweDsgbWFyZ2luOjAgMCA0cHg7fQogIC5tb2RhbCAuc3Vi",
  "e2ZvbnQtc2l6ZToxMi41cHg7IGNvbG9yOnZhcigtLW11dGVkKTsgbWFyZ2luOjAgMCAxOHB4O30K",
  "ICAubW9kYWwgbGFiZWx7ZGlzcGxheTpibG9jazsgZm9udC1zaXplOjEycHg7IGNvbG9yOnZhcigt",
  "LW11dGVkKTsgbWFyZ2luOjEycHggMCA2cHg7IGZvbnQtd2VpZ2h0OjUwMDt9CiAgLm1vZGFsIGlu",
  "cHV0ewogICAgd2lkdGg6MTAwJTsgYmFja2dyb3VuZDp2YXIoLS1wYW5lbC0yKTsgYm9yZGVyOjFw",
  "eCBzb2xpZCB2YXIoLS1saW5lKTsgY29sb3I6dmFyKC0tdGV4dCk7CiAgICBwYWRkaW5nOjExcHgg",
  "MTNweDsgYm9yZGVyLXJhZGl1czoxMHB4OyBmb250LWZhbWlseTonSW50ZXInLHNhbnMtc2VyaWY7",
  "IGZvbnQtc2l6ZToxMy41cHg7CiAgICBvdXRsaW5lOm5vbmU7CiAgfQogIC5tb2RhbCBpbnB1dDpm",
  "b2N1c3tib3JkZXItY29sb3I6dmFyKC0tYnJhc3Mtc29mdCk7IGJveC1zaGFkb3c6MCAwIDAgM3B4",
  "ICNDOTlBMkUxZjt9CiAgLm1vZGFsLWFjdGlvbnN7ZGlzcGxheTpmbGV4OyBnYXA6MTBweDsgbWFy",
  "Z2luLXRvcDoyMHB4O30KICAubW9kYWwtYWN0aW9ucyAuYnRue2ZsZXg6MTsgdGV4dC1hbGlnbjpj",
  "ZW50ZXI7fQogIC5hdXRoLXRhYnN7ZGlzcGxheTpmbGV4OyBnYXA6NnB4OyBiYWNrZ3JvdW5kOnZh",
  "cigtLXBhbmVsLTIpOyBib3JkZXItcmFkaXVzOjEwcHg7IHBhZGRpbmc6NHB4OyBtYXJnaW4tYm90",
  "dG9tOjZweDt9CiAgLmF1dGgtdGFicyBidXR0b257CiAgICBmbGV4OjE7IHBhZGRpbmc6OHB4OyBi",
  "b3JkZXI6bm9uZTsgYmFja2dyb3VuZDpub25lOyBib3JkZXItcmFkaXVzOjdweDsgY3Vyc29yOnBv",
  "aW50ZXI7CiAgICBmb250LXNpemU6MTIuNXB4OyBmb250LXdlaWdodDo2MDA7IGNvbG9yOnZhcigt",
  "LW11dGVkKTsgZm9udC1mYW1pbHk6J0ludGVyJyxzYW5zLXNlcmlmOwogIH0KICAuYXV0aC10YWJz",
  "IGJ1dHRvbi5hY3RpdmV7YmFja2dyb3VuZDp2YXIoLS1wYW5lbCk7IGNvbG9yOnZhcigtLXRleHQp",
  "OyBib3gtc2hhZG93OnZhcigtLXNoYWRvdyk7fQogIC5tb2RhbC1lcnJvcnsKICAgIGRpc3BsYXk6",
  "bm9uZTsgYmFja2dyb3VuZDp2YXIoLS1kYW5nZXItdGludCk7IGNvbG9yOnZhcigtLWRhbmdlcik7",
  "IGJvcmRlcjoxcHggc29saWQgI0MyM0I0QjMwOwogICAgZm9udC1zaXplOjEycHg7IHBhZGRpbmc6",
  "OXB4IDExcHg7IGJvcmRlci1yYWRpdXM6OHB4OyBtYXJnaW4tdG9wOjEycHg7IGZvbnQtd2VpZ2h0",
  "OjUwMDsKICB9CiAgLm1vZGFsLWVycm9yLnNob3d7ZGlzcGxheTpibG9jazt9CiAgLm1vZGFsLW5v",
  "dGV7Zm9udC1zaXplOjExLjVweDsgY29sb3I6dmFyKC0tbXV0ZWQpOyBtYXJnaW4tdG9wOjE0cHg7",
  "IGxpbmUtaGVpZ2h0OjEuNjt9CgogIC5jaGVja291dC1zdW1tYXJ5ewogICAgYmFja2dyb3VuZDp2",
  "YXIoLS1wYW5lbC0yKTsgYm9yZGVyOjFweCBzb2xpZCB2YXIoLS1saW5lKTsgYm9yZGVyLXJhZGl1",
  "czoxMnB4OyBwYWRkaW5nOjE0cHggMTZweDsgbWFyZ2luLXRvcDo2cHg7CiAgfQogIC5jaGVja291",
  "dC1zdW1tYXJ5IC5yb3d7ZGlzcGxheTpmbGV4OyBqdXN0aWZ5LWNvbnRlbnQ6c3BhY2UtYmV0d2Vl",
  "bjsgZm9udC1zaXplOjEzcHg7IG1hcmdpbi1ib3R0b206NnB4O30KICAuY2hlY2tvdXQtc3VtbWFy",
  "eSAucm93Omxhc3QtY2hpbGR7bWFyZ2luLWJvdHRvbTowOyBwYWRkaW5nLXRvcDo4cHg7IGJvcmRl",
  "ci10b3A6MXB4IGRhc2hlZCB2YXIoLS1saW5lKTsgZm9udC13ZWlnaHQ6NzAwO30KICAuZGlzY291",
  "bnQtYXBwbGllZHtjb2xvcjp2YXIoLS1vayk7IGZvbnQtd2VpZ2h0OjYwMDt9CgogIC5yZXN1bHQt",
  "a2V5LWJveHsKICAgIGJhY2tncm91bmQ6dmFyKC0tYnJhc3MtdGludCk7IGJvcmRlcjoxcHggc29s",
  "aWQgI0M5OUEyRTQwOyBib3JkZXItcmFkaXVzOjEycHg7CiAgICBwYWRkaW5nOjE2cHg7IHRleHQt",
  "YWxpZ246Y2VudGVyOyBtYXJnaW4tdG9wOjhweDsKICB9CiAgLnJlc3VsdC1rZXktYm94IGNvZGV7",
  "CiAgICBmb250LWZhbWlseTonSmV0QnJhaW5zIE1vbm8nLG1vbm9zcGFjZTsgZm9udC1zaXplOjE0",
  "cHg7IGZvbnQtd2VpZ2h0OjcwMDsgY29sb3I6dmFyKC0tYnJhc3MpOwogICAgd29yZC1icmVhazpi",
  "cmVhay1hbGw7IGRpc3BsYXk6YmxvY2s7IG1hcmdpbi1ib3R0b206MTBweDsgbGluZS1oZWlnaHQ6",
  "MS41OwogIH0KICAudG9hc3R7CiAgICBwb3NpdGlvbjpmaXhlZDsgYm90dG9tOjI0cHg7IGxlZnQ6",
  "NTAlOyB0cmFuc2Zvcm06dHJhbnNsYXRlWCgtNTAlKSB0cmFuc2xhdGVZKDIwcHgpOwogICAgYmFj",
  "a2dyb3VuZDp2YXIoLS10ZXh0KTsgY29sb3I6I2ZmZjsgcGFkZGluZzoxMnB4IDIwcHg7IGJvcmRl",
  "ci1yYWRpdXM6MTBweDsgZm9udC1zaXplOjEzcHg7CiAgICBvcGFjaXR5OjA7IHBvaW50ZXItZXZl",
  "bnRzOm5vbmU7IHRyYW5zaXRpb246YWxsIC4yNXM7IHotaW5kZXg6MjAwOyBtYXgtd2lkdGg6OTB2",
  "dzsgdGV4dC1hbGlnbjpjZW50ZXI7CiAgfQogIC50b2FzdC5zaG93e29wYWNpdHk6MTsgdHJhbnNm",
  "b3JtOnRyYW5zbGF0ZVgoLTUwJSkgdHJhbnNsYXRlWSgwKTt9CgogIC8qIC0tLS0gVGjDtG5nIHRp",
  "biB0w6BpIGtob+G6o24gLyBs4buLY2ggc+G7rSBu4bqhcCB0aeG7gW4gLyBs4buLY2ggc+G7rSBn",
  "aWFvIGThu4tjaCAtLS0tICovCiAgLmluZm8tcm93e2Rpc3BsYXk6ZmxleDsganVzdGlmeS1jb250",
  "ZW50OnNwYWNlLWJldHdlZW47IGFsaWduLWl0ZW1zOmNlbnRlcjsgcGFkZGluZzoxMHB4IDA7IGJv",
  "cmRlci1ib3R0b206MXB4IGRhc2hlZCB2YXIoLS1saW5lKTsgZm9udC1zaXplOjEzcHg7fQogIC5p",
  "bmZvLXJvdzpsYXN0LWNoaWxke2JvcmRlci1ib3R0b206bm9uZTt9CiAgLmluZm8tcm93IC5re2Nv",
  "bG9yOnZhcigtLW11dGVkKTt9CiAgLmluZm8tcm93IC52e2ZvbnQtd2VpZ2h0OjYwMDsgZm9udC1m",
  "YW1pbHk6J0pldEJyYWlucyBNb25vJyxtb25vc3BhY2U7fQogIC5oaXN0b3J5LWxpc3R7ZGlzcGxh",
  "eTpmbGV4OyBmbGV4LWRpcmVjdGlvbjpjb2x1bW47IGdhcDo4cHg7IG1heC1oZWlnaHQ6MzIwcHg7",
  "IG92ZXJmbG93LXk6YXV0bzsgbWFyZ2luLXRvcDo0cHg7fQogIC5oaXN0b3J5LWl0ZW17CiAgICBk",
  "aXNwbGF5OmZsZXg7IGp1c3RpZnktY29udGVudDpzcGFjZS1iZXR3ZWVuOyBhbGlnbi1pdGVtczpj",
  "ZW50ZXI7IGdhcDoxMHB4OwogICAgYmFja2dyb3VuZDp2YXIoLS1wYW5lbC0yKTsgYm9yZGVyOjFw",
  "eCBzb2xpZCB2YXIoLS1saW5lKTsgYm9yZGVyLXJhZGl1czoxMHB4OyBwYWRkaW5nOjEwcHggMTJw",
  "eDsKICB9CiAgLmhpc3RvcnktaXRlbSAuaC1tYWlue2ZvbnQtc2l6ZToxM3B4OyBmb250LXdlaWdo",
  "dDo2MDA7fQogIC5oaXN0b3J5LWl0ZW0gLmgtc3Vie2ZvbnQtc2l6ZToxMS41cHg7IGNvbG9yOnZh",
  "cigtLW11dGVkKTsgbWFyZ2luLXRvcDoycHg7fQogIC5oaXN0b3J5LWl0ZW0gLmgtYW1vdW50e2Zv",
  "bnQtZmFtaWx5OidKZXRCcmFpbnMgTW9ubycsbW9ub3NwYWNlOyBmb250LXdlaWdodDo3MDA7IGZv",
  "bnQtc2l6ZToxMy41cHg7fQogIC5oaXN0b3J5LWl0ZW0gLmgtYW1vdW50LnBvc3tjb2xvcjp2YXIo",
  "LS1vayk7fQogIC5oaXN0b3J5LWl0ZW0gLmgtYW1vdW50Lm5lZ3tjb2xvcjp2YXIoLS1kYW5nZXIp",
  "O30KICAuaGlzdG9yeS1lbXB0eXt0ZXh0LWFsaWduOmNlbnRlcjsgY29sb3I6dmFyKC0tbXV0ZWQp",
  "OyBmb250LXNpemU6MTIuNXB4OyBwYWRkaW5nOjIwcHggMDt9CiAgLnN0YXR1cy1waWxse2ZvbnQt",
  "c2l6ZToxMC41cHg7IGZvbnQtd2VpZ2h0OjcwMDsgcGFkZGluZzozcHggOXB4OyBib3JkZXItcmFk",
  "aXVzOjIwcHg7IGRpc3BsYXk6aW5saW5lLWJsb2NrO30KICAuc3RhdHVzLXBpbGwucGVuZGluZ3ti",
  "YWNrZ3JvdW5kOnZhcigtLWJyYXNzLXRpbnQpOyBjb2xvcjp2YXIoLS1icmFzcyk7fQogIC5zdGF0",
  "dXMtcGlsbC5hcHByb3ZlZHtiYWNrZ3JvdW5kOnZhcigtLW9rLXRpbnQpOyBjb2xvcjp2YXIoLS1v",
  "ayk7fQogIC5zdGF0dXMtcGlsbC5yZWplY3RlZHtiYWNrZ3JvdW5kOnZhcigtLWRhbmdlci10aW50",
  "KTsgY29sb3I6dmFyKC0tZGFuZ2VyKTt9CiAgLnN0YXR1cy1waWxsLmF2YWlsYWJsZSwgLnN0YXR1",
  "cy1waWxsLnNvbGR7YmFja2dyb3VuZDp2YXIoLS1vay10aW50KTsgY29sb3I6dmFyKC0tb2spO30K",
  "ICAuc3RhdHVzLXBpbGwuYmFubmVkLCAuc3RhdHVzLXBpbGwuZXhwaXJlZHtiYWNrZ3JvdW5kOnZh",
  "cigtLWRhbmdlci10aW50KTsgY29sb3I6dmFyKC0tZGFuZ2VyKTt9CiAgLnN0YXR1cy1waWxsLnVu",
  "YWN0aXZhdGVke2JhY2tncm91bmQ6I0U3RjBGQjsgY29sb3I6IzJENkZCQjt9CgogIC8qIC0tLS0g",
  "UXXhuqNuIGzDvSBrZXkgKGtleSDEkcOjIG11YSkgLS0tLSAqLwogIC5rZXktaXRlbXsKICAgIGJh",
  "Y2tncm91bmQ6dmFyKC0tcGFuZWwtMik7IGJvcmRlcjoxcHggc29saWQgdmFyKC0tbGluZSk7IGJv",
  "cmRlci1yYWRpdXM6MTBweDsgcGFkZGluZzoxMnB4IDE0cHg7CiAgICBkaXNwbGF5OmZsZXg7IGZs",
  "ZXgtZGlyZWN0aW9uOmNvbHVtbjsgZ2FwOjZweDsKICB9CiAgLmtleS1pdGVtIC5rLXRvcHtkaXNw",
  "bGF5OmZsZXg7IGp1c3RpZnktY29udGVudDpzcGFjZS1iZXR3ZWVuOyBhbGlnbi1pdGVtczpjZW50",
  "ZXI7IGdhcDoxMHB4O30KICAua2V5LWl0ZW0gLmstdmFsdWV7Zm9udC1mYW1pbHk6J0pldEJyYWlu",
  "cyBNb25vJyxtb25vc3BhY2U7IGZvbnQtc2l6ZToxMi41cHg7IGZvbnQtd2VpZ2h0OjcwMDsgd29y",
  "ZC1icmVhazpicmVhay1hbGw7fQogIC5rZXktaXRlbSAuay1tZXRhe2ZvbnQtc2l6ZToxMS41cHg7",
  "IGNvbG9yOnZhcigtLW11dGVkKTsgbGluZS1oZWlnaHQ6MS42O30KICAua2V5LWl0ZW0gLmstY29w",
  "eXsKICAgIGFwcGVhcmFuY2U6bm9uZTsgYm9yZGVyOjFweCBzb2xpZCB2YXIoLS1saW5lKTsgYmFj",
  "a2dyb3VuZDp2YXIoLS1wYW5lbCk7IGNvbG9yOnZhcigtLXRleHQpOwogICAgcGFkZGluZzo1cHgg",
  "MTBweDsgYm9yZGVyLXJhZGl1czo3cHg7IGZvbnQtc2l6ZToxMXB4OyBmb250LXdlaWdodDo2MDA7",
  "IGN1cnNvcjpwb2ludGVyOyB3aGl0ZS1zcGFjZTpub3dyYXA7CiAgICBmb250LWZhbWlseTonSW50",
  "ZXInLHNhbnMtc2VyaWY7CiAgfQogIC5rZXktaXRlbSAuay1jb3B5OmhvdmVye2JvcmRlci1jb2xv",
  "cjp2YXIoLS1icmFzcy1zb2Z0KTsgY29sb3I6dmFyKC0tYnJhc3MpO30KCiAgLmJhbmstaW5mby1i",
  "b3h7CiAgICBiYWNrZ3JvdW5kOnZhcigtLXBhbmVsLTIpOyBib3JkZXI6MXB4IHNvbGlkIHZhcigt",
  "LWxpbmUpOyBib3JkZXItcmFkaXVzOjEycHg7IHBhZGRpbmc6MTRweCAxNnB4OyBtYXJnaW4tdG9w",
  "OjZweDsKICB9CiAgLmJhbmstaW5mby1ib3ggLmluZm8tcm93IC52e2ZvbnQtZmFtaWx5OidKZXRC",
  "cmFpbnMgTW9ubycsbW9ub3NwYWNlO30KCiAgLyogLS0tLSBO4bqhcCB0aeG7gW4gdOG7sSDEkeG7",
  "mW5nOiBRUiDEkeG7mW5nIChWaWV0UVIpICsgxJHhu5NuZyBo4buTIMSR4bq/bSBuZ8aw4bujYyAz",
  "MCBwaMO6dCAtLS0tICovCiAgLnRvcHVwLXFyLWJveHsKICAgIGRpc3BsYXk6ZmxleDsgZmxleC1k",
  "aXJlY3Rpb246Y29sdW1uOyBhbGlnbi1pdGVtczpjZW50ZXI7IGdhcDoxMHB4OwogICAgYmFja2dy",
  "b3VuZDp2YXIoLS1wYW5lbC0yKTsgYm9yZGVyOjFweCBzb2xpZCB2YXIoLS1saW5lKTsgYm9yZGVy",
  "LXJhZGl1czoxNHB4OyBwYWRkaW5nOjE4cHggMTZweDsgbWFyZ2luLXRvcDo2cHg7CiAgfQogIC50",
  "b3B1cC1xci1ib3ggaW1newogICAgd2lkdGg6MjIwcHg7IGhlaWdodDoyMjBweDsgb2JqZWN0LWZp",
  "dDpjb250YWluOyBib3JkZXItcmFkaXVzOjEwcHg7IGJhY2tncm91bmQ6I2ZmZjsKICAgIGJvcmRl",
  "cjoxcHggc29saWQgdmFyKC0tbGluZSk7IHBhZGRpbmc6NnB4OwogIH0KICAudG9wdXAtcXItaGlu",
  "dHtmb250LXNpemU6MTJweDsgY29sb3I6dmFyKC0tbXV0ZWQpOyB0ZXh0LWFsaWduOmNlbnRlcjsg",
  "bGluZS1oZWlnaHQ6MS41O30KICAudG9wdXAtY291bnRkb3duewogICAgZGlzcGxheTpmbGV4OyBh",
  "bGlnbi1pdGVtczpjZW50ZXI7IGdhcDo4cHg7IGZvbnQtZmFtaWx5OidKZXRCcmFpbnMgTW9ubycs",
  "bW9ub3NwYWNlOwogICAgZm9udC1zaXplOjIwcHg7IGZvbnQtd2VpZ2h0OjcwMDsgY29sb3I6dmFy",
  "KC0tYnJhc3MpOyBsZXR0ZXItc3BhY2luZzoxcHg7CiAgfQogIC50b3B1cC1jb3VudGRvd24ud2Fy",
  "bntjb2xvcjp2YXIoLS1kYW5nZXIpO30KICAudG9wdXAtY291bnRkb3duLWxhYmVse2ZvbnQtc2l6",
  "ZToxMXB4OyBjb2xvcjp2YXIoLS1tdXRlZCk7IGZvbnQtd2VpZ2h0OjUwMDsgbGV0dGVyLXNwYWNp",
  "bmc6LjNweDsgdGV4dC10cmFuc2Zvcm06dXBwZXJjYXNlOyBmb250LWZhbWlseTonSW50ZXInLHNh",
  "bnMtc2VyaWY7fQogIC50b3B1cC1leHBpcmVkLWJveHsKICAgIGRpc3BsYXk6bm9uZTsgZmxleC1k",
  "aXJlY3Rpb246Y29sdW1uOyBhbGlnbi1pdGVtczpjZW50ZXI7IGdhcDoxMHB4OyB0ZXh0LWFsaWdu",
  "OmNlbnRlcjsKICAgIHBhZGRpbmc6MThweCAxNnB4OwogIH0KICAudG9wdXAtZXhwaXJlZC1ib3gu",
  "c2hvd3tkaXNwbGF5OmZsZXg7fQogIC50b3B1cC1leHBpcmVkLWJveCAuaWNvbnsKICAgIHdpZHRo",
  "OjQ0cHg7IGhlaWdodDo0NHB4OyBib3JkZXItcmFkaXVzOjUwJTsgYmFja2dyb3VuZDp2YXIoLS1k",
  "YW5nZXItdGludCk7IGNvbG9yOnZhcigtLWRhbmdlcik7CiAgICBkaXNwbGF5OmZsZXg7IGFsaWdu",
  "LWl0ZW1zOmNlbnRlcjsganVzdGlmeS1jb250ZW50OmNlbnRlcjsKICB9CiAgLnRvcHVwLXN0ZXAt",
  "YW1vdW50e2Rpc3BsYXk6ZmxleDsgZmxleC1kaXJlY3Rpb246Y29sdW1uOyBnYXA6MTRweDt9CiAg",
  "LnRvcHVwLXN0ZXAtcXJ7ZGlzcGxheTpub25lOyBmbGV4LWRpcmVjdGlvbjpjb2x1bW47IGdhcDox",
  "NHB4O30KICAudG9wdXAtc3RlcC1xci5zaG93e2Rpc3BsYXk6ZmxleDt9CiAgLnRvcHVwLWJhY2st",
  "bGlua3sKICAgIGZvbnQtc2l6ZToxMnB4OyBjb2xvcjp2YXIoLS1tdXRlZCk7IHRleHQtZGVjb3Jh",
  "dGlvbjpub25lOyBmb250LXdlaWdodDo2MDA7IGN1cnNvcjpwb2ludGVyOwogICAgZGlzcGxheTpp",
  "bmxpbmUtZmxleDsgYWxpZ24taXRlbXM6Y2VudGVyOyBnYXA6NXB4OyBhbGlnbi1zZWxmOmZsZXgt",
  "c3RhcnQ7CiAgfQogIC50b3B1cC1iYWNrLWxpbms6aG92ZXJ7Y29sb3I6dmFyKC0tYnJhc3MpO30K",
  "ICAuc3VwcG9ydC1saW5rewogICAgZGlzcGxheTpmbGV4OyBhbGlnbi1pdGVtczpjZW50ZXI7IGdh",
  "cDoxMHB4OyB0ZXh0LWRlY29yYXRpb246bm9uZTsgY29sb3I6dmFyKC0tdGV4dCk7CiAgICBiYWNr",
  "Z3JvdW5kOnZhcigtLXBhbmVsLTIpOyBib3JkZXI6MXB4IHNvbGlkIHZhcigtLWxpbmUpOyBib3Jk",
  "ZXItcmFkaXVzOjEycHg7IHBhZGRpbmc6MTRweCAxNnB4OyBtYXJnaW4tdG9wOjhweDsgZm9udC1z",
  "aXplOjEzLjVweDsgZm9udC13ZWlnaHQ6NjAwOwogIH0KICAuc3VwcG9ydC1saW5rOmhvdmVye2Jv",
  "cmRlci1jb2xvcjp2YXIoLS1icmFzcy1zb2Z0KTt9CiAgLnN1cHBvcnQtbGluayBzdmd7d2lkdGg6",
  "MjBweDsgaGVpZ2h0OjIwcHg7IGNvbG9yOiMyQUFCRUU7IGZsZXgtc2hyaW5rOjA7fQoKICAvKiAt",
  "LS0tIEdldEtleSAodsaw4bujdCBsaW5rIG5o4bqtbiBrZXkpIC0tLS0gKi8KICAuZ2stZ2FtZS1n",
  "cmlke2Rpc3BsYXk6Z3JpZDsgZ3JpZC10ZW1wbGF0ZS1jb2x1bW5zOnJlcGVhdChhdXRvLWZpbGws",
  "IG1pbm1heCgxNDBweCwgMWZyKSk7IGdhcDoxMHB4OyBtYXJnaW4tdG9wOjZweDt9CiAgLmdrLWdh",
  "bWUtY2FyZHsKICAgIGJhY2tncm91bmQ6dmFyKC0tcGFuZWwtMik7IGJvcmRlcjoxcHggc29saWQg",
  "dmFyKC0tbGluZSk7IGJvcmRlci1yYWRpdXM6MTJweDsgcGFkZGluZzoxNHB4IDEwcHg7CiAgICB0",
  "ZXh0LWFsaWduOmNlbnRlcjsgY3Vyc29yOnBvaW50ZXI7IHRyYW5zaXRpb246Ym9yZGVyLWNvbG9y",
  "IC4xMnM7CiAgfQogIC5nay1nYW1lLWNhcmQ6aG92ZXJ7Ym9yZGVyLWNvbG9yOnZhcigtLWJyYXNz",
  "LXNvZnQpO30KICAuZ2stZ2FtZS1jYXJkLnNlbGVjdGVke2JvcmRlci1jb2xvcjp2YXIoLS1icmFz",
  "cyk7IGJhY2tncm91bmQ6dmFyKC0tYnJhc3MtdGludCk7fQogIC5nay1nYW1lLWNhcmQgLmxvZ297",
  "d2lkdGg6NDRweDsgaGVpZ2h0OjQ0cHg7IGJvcmRlci1yYWRpdXM6MTBweDsgbWFyZ2luOjAgYXV0",
  "byA4cHg7IG92ZXJmbG93OmhpZGRlbjsgYmFja2dyb3VuZDp2YXIoLS1wYW5lbCk7IGRpc3BsYXk6",
  "ZmxleDsgYWxpZ24taXRlbXM6Y2VudGVyOyBqdXN0aWZ5LWNvbnRlbnQ6Y2VudGVyOyBmb250LXNp",
  "emU6MjBweDt9CiAgLmdrLWdhbWUtY2FyZCAubG9nbyBpbWd7d2lkdGg6MTAwJTsgaGVpZ2h0OjEw",
  "MCU7IG9iamVjdC1maXQ6Y292ZXI7fQogIC5nay1nYW1lLWNhcmQgLm5hbWV7Zm9udC1zaXplOjEy",
  "LjVweDsgZm9udC13ZWlnaHQ6NjAwO30KICAuZ2stZHVyYXRpb24tbGlzdHtkaXNwbGF5OmZsZXg7",
  "IGZsZXgtZGlyZWN0aW9uOmNvbHVtbjsgZ2FwOjhweDsgbWFyZ2luLXRvcDo2cHg7fQogIC5nay1k",
  "dXJhdGlvbi1pdGVtewogICAgZGlzcGxheTpmbGV4OyBqdXN0aWZ5LWNvbnRlbnQ6c3BhY2UtYmV0",
  "d2VlbjsgYWxpZ24taXRlbXM6Y2VudGVyOyBnYXA6MTBweDsKICAgIGJhY2tncm91bmQ6dmFyKC0t",
  "cGFuZWwtMik7IGJvcmRlcjoxcHggc29saWQgdmFyKC0tbGluZSk7IGJvcmRlci1yYWRpdXM6MTBw",
  "eDsgcGFkZGluZzoxMnB4IDE0cHg7CiAgICBjdXJzb3I6cG9pbnRlcjsKICB9CiAgLmdrLWR1cmF0",
  "aW9uLWl0ZW06aG92ZXJ7Ym9yZGVyLWNvbG9yOnZhcigtLWJyYXNzLXNvZnQpO30KICAuZ2stZHVy",
  "YXRpb24taXRlbS5zZWxlY3RlZHtib3JkZXItY29sb3I6dmFyKC0tYnJhc3MpOyBiYWNrZ3JvdW5k",
  "OnZhcigtLWJyYXNzLXRpbnQpO30KICAuZ2stZHVyYXRpb24taXRlbSAubGJse2ZvbnQtc2l6ZTox",
  "My41cHg7IGZvbnQtd2VpZ2h0OjYwMDt9CiAgLmdrLWR1cmF0aW9uLWl0ZW0gLnJvdW5kc3tmb250",
  "LXNpemU6MTEuNXB4OyBjb2xvcjp2YXIoLS1tdXRlZCk7fQogIC5nay1wcm9ncmVzc3tkaXNwbGF5",
  "OmZsZXg7IGdhcDo2cHg7IGp1c3RpZnktY29udGVudDpjZW50ZXI7IG1hcmdpbjoxNnB4IDA7fQog",
  "IC5nay1wcm9ncmVzcyAuZG90e3dpZHRoOjI4cHg7IGhlaWdodDo2cHg7IGJvcmRlci1yYWRpdXM6",
  "NHB4OyBiYWNrZ3JvdW5kOnZhcigtLWxpbmUpO30KICAuZ2stcHJvZ3Jlc3MgLmRvdC5kb25le2Jh",
  "Y2tncm91bmQ6dmFyKC0tb2spO30KICAuZ2stcHJvZ3Jlc3MgLmRvdC5jdXJyZW50e2JhY2tncm91",
  "bmQ6dmFyKC0tYnJhc3MpO30KICAuZ2stc3RlcC1ib3h7CiAgICBiYWNrZ3JvdW5kOnZhcigtLXBh",
  "bmVsLTIpOyBib3JkZXI6MXB4IHNvbGlkIHZhcigtLWxpbmUpOyBib3JkZXItcmFkaXVzOjEycHg7",
  "IHBhZGRpbmc6MjBweDsgdGV4dC1hbGlnbjpjZW50ZXI7IG1hcmdpbi10b3A6NnB4OwogIH0KICAu",
  "Z2stc3RlcC1ib3ggLnJvdW5kLWxhYmVse2ZvbnQtc2l6ZToxM3B4OyBjb2xvcjp2YXIoLS1tdXRl",
  "ZCk7IG1hcmdpbi1ib3R0b206MTBweDt9Cjwvc3R5bGU+CjwvaGVhZD4KPGJvZHk+Cgo8aGVhZGVy",
  "IGNsYXNzPSJ0b3AiPgogIDxkaXYgY2xhc3M9InRvcC1yb3ciPgogICAgPGRpdiBjbGFzcz0iYnJh",
  "bmQiPgogICAgICA8ZGl2IGNsYXNzPSJtYXJrIj4KICAgICAgICA8c3ZnIHZpZXdCb3g9IjAgMCAy",
  "NCAyNCIgZmlsbD0ibm9uZSIgc3Ryb2tlPSJjdXJyZW50Q29sb3IiIHN0cm9rZS13aWR0aD0iMiI+",
  "PHJlY3QgeD0iMyIgeT0iMTEiIHdpZHRoPSIxOCIgaGVpZ2h0PSIxMCIgcng9IjIiLz48Y2lyY2xl",
  "IGN4PSIxMiIgY3k9IjE2IiByPSIxLjYiLz48cGF0aCBkPSJNNyAxMVY3YTUgNSAwIDAgMSAxMCAw",
  "djQiLz48L3N2Zz4KICAgICAgPC9kaXY+CiAgICAgIDxkaXY+CiAgICAgICAgPGgxPktleVZhdWx0",
  "IFN0b3JlPC9oMT4KICAgICAgICA8ZGl2IGNsYXNzPSJ0YWciPk11YSBrZXkgdHLhu7FjIHR1eeG6",
  "v248L2Rpdj4KICAgICAgPC9kaXY+CiAgICA8L2Rpdj4KICAgIDxkaXYgY2xhc3M9InRvcC1hY3Rp",
  "b25zIj4KICAgICAgPGEgaHJlZj0iL2FkbWluIiBjbGFzcz0iYWRtaW4tbGluayI+VHJhbmcgcXXh",
  "uqNuIHRy4buLPC9hPgogICAgICA8ZGl2IGlkPSJndWVzdEFjdGlvbnMiPgogICAgICAgIDxidXR0",
  "b24gY2xhc3M9ImJ0biIgaWQ9ImJ0bk9wZW5BdXRoIj7EkMSDbmcgbmjhuq1wIC8gxJDEg25nIGvD",
  "vTwvYnV0dG9uPgogICAgICA8L2Rpdj4KICAgICAgPGRpdiBpZD0iYWNjb3VudENoaXAiIGNsYXNz",
  "PSJhY2NvdW50LWNoaXAiIHN0eWxlPSJkaXNwbGF5Om5vbmU7Ij4KICAgICAgICA8c3BhbiBpZD0i",
  "YWNjb3VudE5hbWUiPjwvc3Bhbj4KICAgICAgICA8YnV0dG9uIGlkPSJidG5Mb2dvdXRDdXN0b21l",
  "ciI+xJDEg25nIHh14bqldDwvYnV0dG9uPgogICAgICA8L2Rpdj4KICAgICAgPGRpdiBjbGFzcz0i",
  "bWVudS13cmFwIj4KICAgICAgICA8YnV0dG9uIGNsYXNzPSJoYW1idXJnZXItYnRuIiBpZD0iYnRu",
  "SGFtYnVyZ2VyIiB0aXRsZT0iTWVudSIgYXJpYS1sYWJlbD0iTWVudSI+CiAgICAgICAgICA8c3Zn",
  "IHZpZXdCb3g9IjAgMCAyNCAyNCIgZmlsbD0ibm9uZSIgc3Ryb2tlPSJjdXJyZW50Q29sb3IiIHN0",
  "cm9rZS13aWR0aD0iMiIgc3Ryb2tlLWxpbmVjYXA9InJvdW5kIj48cGF0aCBkPSJNMyA2aDE4TTMg",
  "MTJoMThNMyAxOGgxOCIvPjwvc3ZnPgogICAgICAgIDwvYnV0dG9uPgogICAgICAgIDxkaXYgY2xh",
  "c3M9ImRyb3Bkb3duLW1lbnUiIGlkPSJkcm9wZG93bk1lbnUiPgogICAgICAgICAgPGRpdiBpZD0i",
  "ZGRHdWVzdEJsb2NrIj4KICAgICAgICAgICAgPGJ1dHRvbiBjbGFzcz0iZGQtaXRlbSIgaWQ9ImRk",
  "T3BlbkF1dGgiPgogICAgICAgICAgICAgIDxzdmcgdmlld0JveD0iMCAwIDI0IDI0IiBmaWxsPSJu",
  "b25lIiBzdHJva2U9ImN1cnJlbnRDb2xvciIgc3Ryb2tlLXdpZHRoPSIxLjgiPjxwYXRoIGQ9Ik0x",
  "NSAzaDRhMiAyIDAgMCAxIDIgMnYxNGEyIDIgMCAwIDEtMiAyaC00Ii8+PHBhdGggZD0iTTEwIDE3",
  "bDUtNS01LTUiLz48cGF0aCBkPSJNMTUgMTJIMyIvPjwvc3ZnPgogICAgICAgICAgICAgIMSQxINu",
  "ZyBuaOG6rXAgLyDEkMSDbmcga8O9CiAgICAgICAgICAgIDwvYnV0dG9uPgogICAgICAgICAgPC9k",
  "aXY+CiAgICAgICAgICA8ZGl2IGlkPSJkZEFjY291bnRCbG9jayIgc3R5bGU9ImRpc3BsYXk6bm9u",
  "ZTsiPgogICAgICAgICAgICA8ZGl2IGNsYXNzPSJkZC1hY2NvdW50Ij48YiBpZD0iZGRBY2NvdW50",
  "TmFtZSI+4oCUPC9iPlPhu5EgZMawOiA8c3BhbiBpZD0iZGRBY2NvdW50QmFsYW5jZSI+MOKCqzwv",
  "c3Bhbj48L2Rpdj4KICAgICAgICAgICAgPGRpdiBjbGFzcz0iZGQtc2VwIj48L2Rpdj4KICAgICAg",
  "ICAgICAgPGJ1dHRvbiBjbGFzcz0iZGQtaXRlbSIgaWQ9ImRkVG9wdXAiPgogICAgICAgICAgICAg",
  "IDxzdmcgdmlld0JveD0iMCAwIDI0IDI0IiBmaWxsPSJub25lIiBzdHJva2U9ImN1cnJlbnRDb2xv",
  "ciIgc3Ryb2tlLXdpZHRoPSIxLjgiPjxjaXJjbGUgY3g9IjEyIiBjeT0iMTIiIHI9IjkiLz48cGF0",
  "aCBkPSJNMTIgOHY4TTggMTJoOCIvPjwvc3ZnPgogICAgICAgICAgICAgIE7huqFwIHRp4buBbiB0",
  "4buxIMSR4buZbmcKICAgICAgICAgICAgPC9idXR0b24+CiAgICAgICAgICAgIDxidXR0b24gY2xh",
  "c3M9ImRkLWl0ZW0iIGlkPSJkZEFjY291bnRJbmZvIj4KICAgICAgICAgICAgICA8c3ZnIHZpZXdC",
  "b3g9IjAgMCAyNCAyNCIgZmlsbD0ibm9uZSIgc3Ryb2tlPSJjdXJyZW50Q29sb3IiIHN0cm9rZS13",
  "aWR0aD0iMS44Ij48Y2lyY2xlIGN4PSIxMiIgY3k9IjgiIHI9IjQiLz48cGF0aCBkPSJNNCAyMWMw",
  "LTQgNC02IDgtNnM4IDIgOCA2Ii8+PC9zdmc+CiAgICAgICAgICAgICAgVGjDtG5nIHRpbiB0w6Bp",
  "IGtob+G6o24KICAgICAgICAgICAgPC9idXR0b24+CiAgICAgICAgICAgIDxidXR0b24gY2xhc3M9",
  "ImRkLWl0ZW0iIGlkPSJkZFRvcHVwSGlzdG9yeSI+CiAgICAgICAgICAgICAgPHN2ZyB2aWV3Qm94",
  "PSIwIDAgMjQgMjQiIGZpbGw9Im5vbmUiIHN0cm9rZT0iY3VycmVudENvbG9yIiBzdHJva2Utd2lk",
  "dGg9IjEuOCI+PHBhdGggZD0iTTMgMTJhOSA5IDAgMSAwIDMtNi43Ii8+PHBhdGggZD0iTTMgNHY1",
  "aDUiLz48cGF0aCBkPSJNMTIgN3Y1bDQgMiIvPjwvc3ZnPgogICAgICAgICAgICAgIEzhu4tjaCBz",
  "4butIG7huqFwIHRp4buBbgogICAgICAgICAgICA8L2J1dHRvbj4KICAgICAgICAgICAgPGJ1dHRv",
  "biBjbGFzcz0iZGQtaXRlbSIgaWQ9ImRkVHhIaXN0b3J5Ij4KICAgICAgICAgICAgICA8c3ZnIHZp",
  "ZXdCb3g9IjAgMCAyNCAyNCIgZmlsbD0ibm9uZSIgc3Ryb2tlPSJjdXJyZW50Q29sb3IiIHN0cm9r",
  "ZS13aWR0aD0iMS44Ij48cmVjdCB4PSIzIiB5PSI0IiB3aWR0aD0iMTgiIGhlaWdodD0iMTYiIHJ4",
  "PSIyIi8+PHBhdGggZD0iTTcgOWgxME03IDEzaDEwTTcgMTdoNiIvPjwvc3ZnPgogICAgICAgICAg",
  "ICAgIEzhu4tjaCBz4butIGdpYW8gZOG7i2NoCiAgICAgICAgICAgIDwvYnV0dG9uPgogICAgICAg",
  "ICAgICA8YnV0dG9uIGNsYXNzPSJkZC1pdGVtIiBpZD0iZGRNeUtleXMiPgogICAgICAgICAgICAg",
  "IDxzdmcgdmlld0JveD0iMCAwIDI0IDI0IiBmaWxsPSJub25lIiBzdHJva2U9ImN1cnJlbnRDb2xv",
  "ciIgc3Ryb2tlLXdpZHRoPSIxLjgiPjxyZWN0IHg9IjMiIHk9IjExIiB3aWR0aD0iMTgiIGhlaWdo",
  "dD0iMTAiIHJ4PSIyIi8+PGNpcmNsZSBjeD0iMTIiIGN5PSIxNiIgcj0iMS42Ii8+PHBhdGggZD0i",
  "TTcgMTFWN2E1IDUgMCAwIDEgMTAgMHY0Ii8+PC9zdmc+CiAgICAgICAgICAgICAgUXXhuqNuIGzD",
  "vSBrZXkKICAgICAgICAgICAgPC9idXR0b24+CiAgICAgICAgICAgIDxkaXYgY2xhc3M9ImRkLXNl",
  "cCI+PC9kaXY+CiAgICAgICAgICA8L2Rpdj4KICAgICAgICAgIDxidXR0b24gY2xhc3M9ImRkLWl0",
  "ZW0iIGlkPSJkZFN1cHBvcnQiPgogICAgICAgICAgICA8c3ZnIHZpZXdCb3g9IjAgMCAyNCAyNCIg",
  "ZmlsbD0ibm9uZSIgc3Ryb2tlPSJjdXJyZW50Q29sb3IiIHN0cm9rZS13aWR0aD0iMS44Ij48cGF0",
  "aCBkPSJNMjIgNC45IDIuNSAxMi4zYy0uOS4zNS0uOSAxLjYuMDUgMS45bDQuNyAxLjUgMS44IDUu",
  "NGMuMy45IDEuNSAxLjA1IDIuMDUuMjVsMi40LTMuNSA0LjYgMy40Yy44LjYgMS45NS4xNSAyLjE1",
  "LS44NUwyMy45IDUuOWMuMi0xLS44NS0xLjc1LTEuOS0xeiIvPjwvc3ZnPgogICAgICAgICAgICBI",
  "4buXIHRy4bujIGtow6FjaCBow6BuZwogICAgICAgICAgPC9idXR0b24+CiAgICAgICAgICA8YnV0",
  "dG9uIGNsYXNzPSJkZC1pdGVtIiBpZD0iZGRHZXRLZXkiPgogICAgICAgICAgICA8c3ZnIHZpZXdC",
  "b3g9IjAgMCAyNCAyNCIgZmlsbD0ibm9uZSIgc3Ryb2tlPSJjdXJyZW50Q29sb3IiIHN0cm9rZS13",
  "aWR0aD0iMS44Ij48Y2lyY2xlIGN4PSI4IiBjeT0iMTUiIHI9IjQiLz48cGF0aCBkPSJNMTAuNSAx",
  "Mi41IDIwIDNNMjAgM2gtNE0yMCAzdjQiLz48L3N2Zz4KICAgICAgICAgICAgR2V0S2V5ICh2xrDh",
  "u6N0IGxpbmsgbmjhuq1uIGtleSkKICAgICAgICAgIDwvYnV0dG9uPgogICAgICAgIDwvZGl2Pgog",
  "ICAgICA8L2Rpdj4KICAgIDwvZGl2PgogIDwvZGl2Pgo8L2hlYWRlcj4KCjxtYWluPgogIDxkaXYg",
  "Y2xhc3M9Imhlcm8iPgogICAgPGgyPktleSBjaMOtbmggaMOjbmcg4oCUIGdpYW8gbmdheSBzYXUg",
  "a2hpIHRoYW5oIHRvw6FuPC9oMj4KICAgIDxwPkNo4buNbiBz4bqjbiBwaOG6qW0gYsOqbiBkxrDh",
  "u5tpLCDEkcSDbmcgbmjhuq1wIGhv4bq3YyB04bqhbyB0w6BpIGtob+G6o24sIMOhcCBtw6MgZ2nh",
  "uqNtIGdpw6EgKG7hur91IGPDsykgdsOgIG5o4bqtbiBrZXkgbmdheSBs4bqtcCB04bupYy48L3A+",
  "CiAgICA8ZGl2IGNsYXNzPSJiYWRnZXMiPgogICAgICA8c3BhbiBjbGFzcz0iYmFkZ2UiPvCflJIg",
  "QuG6o28gbeG6rXQgwrcgYW4gdG/DoG48L3NwYW4+CiAgICAgIDxzcGFuIGNsYXNzPSJiYWRnZSI+",
  "4pqhIEdpYW8ga2V5IHThu7EgxJHhu5luZzwvc3Bhbj4KICAgICAgPHNwYW4gY2xhc3M9ImJhZGdl",
  "Ij7wn46f77iPIEjhu5cgdHLhu6MgbcOjIGdp4bqjbSBnacOhPC9zcGFuPgogICAgPC9kaXY+CiAg",
  "PC9kaXY+CgogIDxkaXYgY2xhc3M9ImdyaWQiIGlkPSJwcm9kdWN0R3JpZCI+PC9kaXY+CiAgPGRp",
  "diBjbGFzcz0iZW1wdHktc3RhdGUiIGlkPSJlbXB0eVN0YXRlIiBzdHlsZT0iZGlzcGxheTpub25l",
  "OyI+CiAgICA8ZGl2IGNsYXNzPSJiaWciPkhp4buHbiBjaMawYSBjw7Mgc+G6o24gcGjhuqltIG7D",
  "oG88L2Rpdj4KICAgIFF14bqjbiB0cuG7iyB2acOqbiBjaMawYSB0aMOqbSBz4bqjbiBwaOG6qW0g",
  "bsOgbyBsw6puIHRyYW5nIGLDoW4ga2V5LiBWdWkgbMOybmcgcXVheSBs4bqhaSBzYXUuCiAgPC9k",
  "aXY+CgogIDxkaXYgY2xhc3M9ImdyaWQiIGlkPSJwZ0dyaWQiIHN0eWxlPSJtYXJnaW4tdG9wOjE4",
  "cHg7Ij48L2Rpdj4KCiAgPGRpdiBzdHlsZT0iZGlzcGxheTpmbGV4OyBhbGlnbi1pdGVtczpiYXNl",
  "bGluZTsganVzdGlmeS1jb250ZW50OnNwYWNlLWJldHdlZW47IG1hcmdpbjozNnB4IDAgMTRweDsi",
  "PgogICAgPGgyIHN0eWxlPSJmb250LWZhbWlseTonU3BhY2UgR3JvdGVzaycsc2Fucy1zZXJpZjsg",
  "Zm9udC1zaXplOjIwcHg7IG1hcmdpbjowOyI+RGFuaCBzw6FjaCBnYW1lIChHZXRLZXkg4oCUIHbG",
  "sOG7o3QgbGluayBuaOG6rW4ga2V5KTwvaDI+CiAgICA8c3BhbiBjbGFzcz0ic3ViIiBpZD0iZ2tH",
  "YW1lQ291bnRMYWJlbCIgc3R5bGU9ImZvbnQtc2l6ZToxMi41cHg7IGNvbG9yOnZhcigtLW11dGVk",
  "KTsiPjAgZ2FtZTwvc3Bhbj4KICA8L2Rpdj4KICA8ZGl2IGNsYXNzPSJncmlkIiBpZD0iZ2tHYW1l",
  "R3JpZEhvbWUiPjwvZGl2PgogIDxkaXYgY2xhc3M9ImVtcHR5LXN0YXRlIiBpZD0iZ2tHYW1lRW1w",
  "dHlTdGF0ZUhvbWUiIHN0eWxlPSJkaXNwbGF5Om5vbmU7Ij4KICAgIDxkaXYgY2xhc3M9ImJpZyI+",
  "SGnhu4duIGNoxrBhIGPDsyBnYW1lIEdldEtleSBuw6BvPC9kaXY+CiAgICBRdeG6o24gdHLhu4sg",
  "dmnDqm4gY2jGsGEgdGjDqm0gZ2FtZSBuw6BvLiBWdWkgbMOybmcgcXVheSBs4bqhaSBzYXUuCiAg",
  "PC9kaXY+CjwvbWFpbj4KCjxmb290ZXI+S2V5VmF1bHQgU3RvcmUg4oCUIEjhu4cgdGjhu5FuZyBi",
  "4bqjbyBt4bqtdCDCtyBhbiB0b8OgbiDCtyBjaOG6pXQgbMaw4bujbmcuPC9mb290ZXI+Cgo8IS0t",
  "ID09PT09PT09PT09PSBNT0RBTDogxJDEgk5HIE5I4bqsUCAvIMSQxIJORyBLw50gPT09PT09PT09",
  "PT09IC0tPgo8ZGl2IGNsYXNzPSJtb2RhbC1iZyIgaWQ9ImF1dGhNb2RhbEJnIj4KICA8ZGl2IGNs",
  "YXNzPSJtb2RhbCI+CiAgICA8aDM+VMOgaSBraG/huqNuIGPhu6dhIGLhuqFuPC9oMz4KICAgIDxw",
  "IGNsYXNzPSJzdWIiPkPhuqduIMSRxINuZyBuaOG6rXAgaG/hurdjIHThuqFvIHTDoGkga2hv4bqj",
  "biDEkeG7gyBtdWEga2V5LjwvcD4KICAgIDxkaXYgY2xhc3M9ImF1dGgtdGFicyI+CiAgICAgIDxi",
  "dXR0b24gaWQ9InRhYkxvZ2luIiBjbGFzcz0iYWN0aXZlIj7EkMSDbmcgbmjhuq1wPC9idXR0b24+",
  "CiAgICAgIDxidXR0b24gaWQ9InRhYlJlZ2lzdGVyIj7EkMSDbmcga8O9PC9idXR0b24+CiAgICA8",
  "L2Rpdj4KCiAgICA8ZGl2IGlkPSJhdXRoRm9ybUxvZ2luIj4KICAgICAgPGxhYmVsPlTDqm4gxJHE",
  "g25nIG5o4bqtcDwvbGFiZWw+CiAgICAgIDxpbnB1dCB0eXBlPSJ0ZXh0IiBpZD0ibG9naW5Vc2Vy",
  "bmFtZSIgcGxhY2Vob2xkZXI9Ik5o4bqtcCB0w6puIMSRxINuZyBuaOG6rXAiPgogICAgICA8bGFi",
  "ZWw+TeG6rXQga2jhuql1PC9sYWJlbD4KICAgICAgPGlucHV0IHR5cGU9InBhc3N3b3JkIiBpZD0i",
  "bG9naW5QYXNzd29yZCIgcGxhY2Vob2xkZXI9Ik5o4bqtcCBt4bqtdCBraOG6qXUiPgogICAgPC9k",
  "aXY+CgogICAgPGRpdiBpZD0iYXV0aEZvcm1SZWdpc3RlciIgc3R5bGU9ImRpc3BsYXk6bm9uZTsi",
  "PgogICAgICA8bGFiZWw+VMOqbiDEkcSDbmcgbmjhuq1wPC9sYWJlbD4KICAgICAgPGlucHV0IHR5",
  "cGU9InRleHQiIGlkPSJyZWdVc2VybmFtZSIgcGxhY2Vob2xkZXI9IkNo4buNbiB0w6puIMSRxINu",
  "ZyBuaOG6rXAiPgogICAgICA8bGFiZWw+TeG6rXQga2jhuql1PC9sYWJlbD4KICAgICAgPGlucHV0",
  "IHR5cGU9InBhc3N3b3JkIiBpZD0icmVnUGFzc3dvcmQiIHBsYWNlaG9sZGVyPSJU4buRaSB0aGnh",
  "u4N1IDgga8O9IHThu7EiPgogICAgICA8bGFiZWw+Tmjhuq1wIGzhuqFpIG3huq10IGto4bqpdTwv",
  "bGFiZWw+CiAgICAgIDxpbnB1dCB0eXBlPSJwYXNzd29yZCIgaWQ9InJlZ1Bhc3N3b3JkQ29uZmly",
  "bSIgcGxhY2Vob2xkZXI9Ik5o4bqtcCBs4bqhaSBt4bqtdCBraOG6qXUiPgogICAgPC9kaXY+Cgog",
  "ICAgPGRpdiBjbGFzcz0ibW9kYWwtZXJyb3IiIGlkPSJhdXRoRXJyb3IiPjwvZGl2PgoKICAgIDxk",
  "aXYgY2xhc3M9Im1vZGFsLWFjdGlvbnMiPgogICAgICA8YnV0dG9uIGNsYXNzPSJidG4gYnRuLWdo",
  "b3N0IiBpZD0iYnRuQ2xvc2VBdXRoIj7EkMOzbmc8L2J1dHRvbj4KICAgICAgPGJ1dHRvbiBjbGFz",
  "cz0iYnRuIiBpZD0iYnRuU3VibWl0QXV0aCI+xJDEg25nIG5o4bqtcDwvYnV0dG9uPgogICAgPC9k",
  "aXY+CiAgPC9kaXY+CjwvZGl2PgoKPCEtLSA9PT09PT09PT09PT0gTU9EQUw6IFRIQU5IIFRPw4FO",
  "ID09PT09PT09PT09PSAtLT4KPGRpdiBjbGFzcz0ibW9kYWwtYmciIGlkPSJjaGVja291dE1vZGFs",
  "QmciPgogIDxkaXYgY2xhc3M9Im1vZGFsIj4KICAgIDxoMz5Yw6FjIG5o4bqtbiBtdWEga2V5PC9o",
  "Mz4KICAgIDxwIGNsYXNzPSJzdWIiIGlkPSJjaGVja291dFByb2R1Y3ROYW1lIj7igJQ8L3A+Cgog",
  "ICAgPGxhYmVsPk3DoyBnaeG6o20gZ2nDoSAobuG6v3UgY8OzKTwvbGFiZWw+CiAgICA8ZGl2IHN0",
  "eWxlPSJkaXNwbGF5OmZsZXg7IGdhcDo4cHg7Ij4KICAgICAgPGlucHV0IHR5cGU9InRleHQiIGlk",
  "PSJjaGVja291dERpc2NvdW50Q29kZSIgcGxhY2Vob2xkZXI9IlZEOiBTQUxFMjAiIHN0eWxlPSJm",
  "bGV4OjE7IHRleHQtdHJhbnNmb3JtOnVwcGVyY2FzZTsiPgogICAgICA8YnV0dG9uIGNsYXNzPSJi",
  "dG4gYnRuLWdob3N0IiBpZD0iYnRuQXBwbHlEaXNjb3VudCIgc3R5bGU9IndoaXRlLXNwYWNlOm5v",
  "d3JhcDsiPsOBcCBk4bulbmc8L2J1dHRvbj4KICAgIDwvZGl2PgoKICAgIDxkaXYgY2xhc3M9ImNo",
  "ZWNrb3V0LXN1bW1hcnkiPgogICAgICA8ZGl2IGNsYXNzPSJyb3ciPjxzcGFuPkdpw6EgZ+G7kWM8",
  "L3NwYW4+PHNwYW4gaWQ9ImNoZWNrb3V0T3JpZ2luYWxQcmljZSI+MOKCqzwvc3Bhbj48L2Rpdj4K",
  "ICAgICAgPGRpdiBjbGFzcz0icm93IiBpZD0iY2hlY2tvdXREaXNjb3VudFJvdyIgc3R5bGU9ImRp",
  "c3BsYXk6bm9uZTsiPjxzcGFuPkdp4bqjbSBnacOhPC9zcGFuPjxzcGFuIGNsYXNzPSJkaXNjb3Vu",
  "dC1hcHBsaWVkIiBpZD0iY2hlY2tvdXREaXNjb3VudEFtb3VudCI+MOKCqzwvc3Bhbj48L2Rpdj4K",
  "ICAgICAgPGRpdiBjbGFzcz0icm93Ij48c3Bhbj5UaMOgbmggdGnhu4FuPC9zcGFuPjxzcGFuIGlk",
  "PSJjaGVja291dEZpbmFsUHJpY2UiPjDigqs8L3NwYW4+PC9kaXY+CiAgICA8L2Rpdj4KCiAgICA8",
  "ZGl2IGNsYXNzPSJtb2RhbC1lcnJvciIgaWQ9ImNoZWNrb3V0RXJyb3IiPjwvZGl2PgogICAgPHAg",
  "Y2xhc3M9Im1vZGFsLW5vdGUiPlNhdSBraGkgeMOhYyBuaOG6rW4sIGjhu4cgdGjhu5FuZyBz4bq9",
  "IGdpYW8gbmdheSAxIGtleSBjw7JuIGjDoG5nIGNobyB0w6BpIGtob+G6o24gY+G7p2EgYuG6oW4u",
  "PC9wPgoKICAgIDxkaXYgY2xhc3M9Im1vZGFsLWFjdGlvbnMiPgogICAgICA8YnV0dG9uIGNsYXNz",
  "PSJidG4gYnRuLWdob3N0IiBpZD0iYnRuQ2xvc2VDaGVja291dCI+SHXhu7c8L2J1dHRvbj4KICAg",
  "ICAgPGJ1dHRvbiBjbGFzcz0iYnRuIiBpZD0iYnRuQ29uZmlybUNoZWNrb3V0Ij5Yw6FjIG5o4bqt",
  "biBtdWE8L2J1dHRvbj4KICAgIDwvZGl2PgogIDwvZGl2Pgo8L2Rpdj4KCjwhLS0gPT09PT09PT09",
  "PT09IE1PREFMOiBDSOG7jE4gR8OTSSAoTkjDk00gU+G6ok4gUEjhuqhNLCBHSeG7kE5HIEdFVEtF",
  "WSkgPT09PT09PT09PT09IC0tPgo8IS0tID09PT09PT09PT09PSBNT0RBTDogQ0jhu4xOIEfDk0kg",
  "SOG7olAgTkjhuqRUIChkw7luZyBjaHVuZyBjaG8gR2V0S2V5ICYgc+G6o24gcGjhuqltIG11YSBi",
  "4bqxbmcgdGnhu4FuKSA9PT09PT09PT09PT0gLS0+CjxkaXYgY2xhc3M9Im1vZGFsLWJnIiBpZD0i",
  "dW5pZmllZFBsYW5Nb2RhbEJnIj4KICA8ZGl2IGNsYXNzPSJtb2RhbCI+CiAgICA8ZGl2IGNsYXNz",
  "PSJ1bmlmaWVkLXBsYW4taGVhZGVyIj4KICAgICAgPGRpdiBjbGFzcz0ibG9nbyIgaWQ9InVuaWZp",
  "ZWRQbGFuTG9nbyI+8J+TpjwvZGl2PgogICAgICA8ZGl2PgogICAgICAgIDxoMyBpZD0idW5pZmll",
  "ZFBsYW5UaXRsZSI+4oCUPC9oMz4KICAgICAgICA8cCBjbGFzcz0ic3ViMiIgaWQ9InVuaWZpZWRQ",
  "bGFuU3VidGl0bGUiPuKAlDwvcD4KICAgICAgPC9kaXY+CiAgICA8L2Rpdj4KICAgIDxkaXYgaWQ9",
  "InVuaWZpZWRQbGFuTGlzdCIgc3R5bGU9ImRpc3BsYXk6ZmxleDsgZmxleC1kaXJlY3Rpb246Y29s",
  "dW1uOyBnYXA6MTBweDsgbWFyZ2luOjE2cHggMDsiPjwvZGl2PgogICAgPGRpdiBjbGFzcz0ibW9k",
  "YWwtZXJyb3IiIGlkPSJ1bmlmaWVkUGxhbkVycm9yIj48L2Rpdj4KICAgIDxkaXYgY2xhc3M9Im1v",
  "ZGFsLWFjdGlvbnMiPgogICAgICA8YnV0dG9uIGNsYXNzPSJidG4gYnRuLWdob3N0IiBpZD0iYnRu",
  "Q2xvc2VVbmlmaWVkUGxhbiIgc3R5bGU9IndpZHRoOjEwMCU7Ij7EkMOzbmc8L2J1dHRvbj4KICAg",
  "IDwvZGl2PgogIDwvZGl2Pgo8L2Rpdj4KCjwhLS0gPT09PT09PT09PT09IE1PREFMOiBL4bq+VCBR",
  "VeG6oiBNVUEgS0VZID09PT09PT09PT09PSAtLT4KPGRpdiBjbGFzcz0ibW9kYWwtYmciIGlkPSJy",
  "ZXN1bHRNb2RhbEJnIj4KICA8ZGl2IGNsYXNzPSJtb2RhbCI+CiAgICA8aDM+8J+OiSBNdWEga2V5",
  "IHRow6BuaCBjw7RuZyE8L2gzPgogICAgPHAgY2xhc3M9InN1YiI+S2V5IGPhu6dhIGLhuqFuIMSR",
  "w6Mgc+G6tW4gc8OgbmcsIHZ1aSBsw7JuZyBsxrB1IGzhuqFpIGPhuqluIHRo4bqtbi48L3A+CiAg",
  "ICA8ZGl2IGNsYXNzPSJyZXN1bHQta2V5LWJveCI+CiAgICAgIDxjb2RlIGlkPSJyZXN1bHRLZXlW",
  "YWx1ZSI+4oCUPC9jb2RlPgogICAgICA8YnV0dG9uIGNsYXNzPSJidG4iIGlkPSJidG5Db3B5UmVz",
  "dWx0S2V5IiBzdHlsZT0id2lkdGg6MTAwJTsiPlNhbyBjaMOpcCBrZXk8L2J1dHRvbj4KICAgIDwv",
  "ZGl2PgogICAgPHAgY2xhc3M9Im1vZGFsLW5vdGUiIGlkPSJyZXN1bHRLZXlNZXRhIj48L3A+CiAg",
  "ICA8ZGl2IGNsYXNzPSJtb2RhbC1hY3Rpb25zIj4KICAgICAgPGJ1dHRvbiBjbGFzcz0iYnRuIGJ0",
  "bi1naG9zdCIgaWQ9ImJ0bkNsb3NlUmVzdWx0IiBzdHlsZT0id2lkdGg6MTAwJTsiPsSQw7NuZzwv",
  "YnV0dG9uPgogICAgPC9kaXY+CiAgPC9kaXY+CjwvZGl2PgoKPCEtLSA9PT09PT09PT09PT0gTU9E",
  "QUw6IFRIw5RORyBUSU4gVMOASSBLSE/huqJOID09PT09PT09PT09PSAtLT4KPGRpdiBjbGFzcz0i",
  "bW9kYWwtYmciIGlkPSJhY2NvdW50SW5mb01vZGFsQmciPgogIDxkaXYgY2xhc3M9Im1vZGFsIj4K",
  "ICAgIDxoMz5UaMO0bmcgdGluIHTDoGkga2hv4bqjbjwvaDM+CiAgICA8cCBjbGFzcz0ic3ViIj5U",
  "aMO0bmcgdGluIHTDoGkga2hv4bqjbiBraMOhY2ggaMOgbmcgY+G7p2EgYuG6oW4uPC9wPgogICAg",
  "PGRpdiBjbGFzcz0iaW5mby1yb3ciPjxzcGFuIGNsYXNzPSJrIj5Uw6puIMSRxINuZyBuaOG6rXA8",
  "L3NwYW4+PHNwYW4gY2xhc3M9InYiIGlkPSJpbmZvVXNlcm5hbWUiPuKAlDwvc3Bhbj48L2Rpdj4K",
  "ICAgIDxkaXYgY2xhc3M9ImluZm8tcm93Ij48c3BhbiBjbGFzcz0iayI+U+G7kSBkxrAgaGnhu4du",
  "IHThuqFpPC9zcGFuPjxzcGFuIGNsYXNzPSJ2IiBpZD0iaW5mb0JhbGFuY2UiPjDigqs8L3NwYW4+",
  "PC9kaXY+CiAgICA8ZGl2IGNsYXNzPSJpbmZvLXJvdyI+PHNwYW4gY2xhc3M9ImsiPlZhaSB0csOy",
  "PC9zcGFuPjxzcGFuIGNsYXNzPSJ2IiBpZD0iaW5mb1JvbGUiPktow6FjaCBow6BuZzwvc3Bhbj48",
  "L2Rpdj4KICAgIDxkaXYgY2xhc3M9Im1vZGFsLWFjdGlvbnMiPgogICAgICA8YnV0dG9uIGNsYXNz",
  "PSJidG4gYnRuLWdob3N0IiBpZD0iYnRuQ2xvc2VBY2NvdW50SW5mbyIgc3R5bGU9IndpZHRoOjEw",
  "MCU7Ij7EkMOzbmc8L2J1dHRvbj4KICAgIDwvZGl2PgogIDwvZGl2Pgo8L2Rpdj4KCjwhLS0gPT09",
  "PT09PT09PT09IE1PREFMOiBO4bqgUCBUSeG7gE4gVOG7sCDEkOG7mE5HID09PT09PT09PT09PSAt",
  "LT4KPGRpdiBjbGFzcz0ibW9kYWwtYmciIGlkPSJ0b3B1cE1vZGFsQmcyIj4KICA8ZGl2IGNsYXNz",
  "PSJtb2RhbCI+CgogICAgPCEtLSBCxrDhu5tjIDE6IG5o4bqtcCBz4buRIHRp4buBbiBtdeG7kW4g",
  "buG6oXAgLS0+CiAgICA8ZGl2IGNsYXNzPSJ0b3B1cC1zdGVwLWFtb3VudCIgaWQ9InRvcHVwU3Rl",
  "cEFtb3VudCI+CiAgICAgIDxkaXY+CiAgICAgICAgPGgzPk7huqFwIHRp4buBbiB2w6BvIHTDoGkg",
  "a2hv4bqjbjwvaDM+CiAgICAgICAgPHAgY2xhc3M9InN1YiI+Tmjhuq1wIHPhu5EgdGnhu4FuIGLh",
  "uqFuIG114buRbiBu4bqhcCwgaOG7hyB0aOG7kW5nIHPhur0gdOG6oW8gbcOjIFFSIGNodXnhu4Nu",
  "IGtob+G6o24gcmnDqm5nIGNobyB5w6p1IGPhuqd1IG7DoHkgKGPDsyBoaeG7h3UgbOG7sWMgdHJv",
  "bmcgMzAgcGjDunQpLjwvcD4KICAgICAgPC9kaXY+CgogICAgICA8bGFiZWw+U+G7kSB0aeG7gW4g",
  "bXXhu5FuIG7huqFwICjigqspPC9sYWJlbD4KICAgICAgPGlucHV0IHR5cGU9InRleHQiIGlkPSJ0",
  "b3B1cFJlcXVlc3RBbW91bnQiIHBsYWNlaG9sZGVyPSJWRDogMTAwMDAwIiBpbnB1dG1vZGU9Im51",
  "bWVyaWMiPgoKICAgICAgPGRpdiBjbGFzcz0ibW9kYWwtZXJyb3IiIGlkPSJ0b3B1cFJlcXVlc3RF",
  "cnJvciI+PC9kaXY+CgogICAgICA8ZGl2IGNsYXNzPSJtb2RhbC1hY3Rpb25zIj4KICAgICAgICA8",
  "YnV0dG9uIGNsYXNzPSJidG4gYnRuLWdob3N0IiBpZD0iYnRuQ2xvc2VUb3B1cDIiPkh14bu3PC9i",
  "dXR0b24+CiAgICAgICAgPGJ1dHRvbiBjbGFzcz0iYnRuIiBpZD0iYnRuU3VibWl0VG9wdXBSZXF1",
  "ZXN0Ij5U4bqhbyBtw6MgUVIgbuG6oXAgdGnhu4FuPC9idXR0b24+CiAgICAgIDwvZGl2PgogICAg",
  "PC9kaXY+CgogICAgPCEtLSBCxrDhu5tjIDI6IGhp4buHbiBRUiDEkeG7mW5nICjEkcOjIG5ow7pu",
  "ZyBz4buRIHRp4buBbiArIG7hu5lpIGR1bmcgQ0spICsgxJHhu5NuZyBo4buTIMSR4bq/bSBuZ8aw",
  "4bujYyAzMCBwaMO6dCAtLT4KICAgIDxkaXYgY2xhc3M9InRvcHVwLXN0ZXAtcXIiIGlkPSJ0b3B1",
  "cFN0ZXBRciI+CiAgICAgIDxzcGFuIGNsYXNzPSJ0b3B1cC1iYWNrLWxpbmsiIGlkPSJidG5CYWNr",
  "VG9wdXBBbW91bnQiPuKAuSDEkOG7lWkgc+G7kSB0aeG7gW4ga2jDoWM8L3NwYW4+CiAgICAgIDxk",
  "aXY+CiAgICAgICAgPGgzPlF1w6l0IG3DoyBRUiDEkeG7gyBjaHV54buDbiBraG/huqNuPC9oMz4K",
  "ICAgICAgICA8cCBjbGFzcz0ic3ViIj5N4bufIGFwcCBuZ8OibiBow6BuZywgcXXDqXQgbcOjIFFS",
  "IGLDqm4gZMaw4bubaSDigJQgc+G7kSB0aeG7gW4gdsOgIG7hu5lpIGR1bmcgY2h1eeG7g24ga2hv",
  "4bqjbiDEkcOjIMSRxrDhu6NjIMSRaeG7gW4gc+G6tW4uIFNhdSBraGkgY2h1eeG7g24ga2hv4bqj",
  "biB4b25nLCBxdeG6o24gdHLhu4sgdmnDqm4gc+G6vSBkdXnhu4d0IHbDoCBj4buZbmcgdGnhu4Fu",
  "IHbDoG8gdMOgaSBraG/huqNuIGPhu6dhIGLhuqFuLjwvcD4KICAgICAgPC9kaXY+CgogICAgICA8",
  "ZGl2IGNsYXNzPSJ0b3B1cC1xci1ib3giIGlkPSJ0b3B1cFFyQm94Ij4KICAgICAgICA8aW1nIGlk",
  "PSJ0b3B1cFFySW1nIiBzcmM9IiIgYWx0PSJNw6MgUVIgbuG6oXAgdGnhu4FuIj4KICAgICAgICA8",
  "ZGl2IGNsYXNzPSJ0b3B1cC1xci1oaW50Ij5OZ8OibiBow6BuZzogPGI+TUIgQmFuazwvYj4gwrcg",
  "U1RLOiA8YiBpZD0idG9wdXBRckFjY291bnRObyI+4oCUPC9iPiDCtyBDVEs6IDxiIGlkPSJ0b3B1",
  "cFFyQWNjb3VudE5hbWUiPuKAlDwvYj48L2Rpdj4KICAgICAgICA8ZGl2IGNsYXNzPSJ0b3B1cC1x",
  "ci1oaW50Ij5T4buRIHRp4buBbjogPGIgaWQ9InRvcHVwUXJBbW91bnQiPjDigqs8L2I+IMK3IE7h",
  "u5lpIGR1bmcgQ0s6IDxiIGlkPSJ0b3B1cFFyTm90ZSI+4oCUPC9iPjwvZGl2PgogICAgICA8L2Rp",
  "dj4KCiAgICAgIDxkaXYgc3R5bGU9ImRpc3BsYXk6ZmxleDsgZmxleC1kaXJlY3Rpb246Y29sdW1u",
  "OyBhbGlnbi1pdGVtczpjZW50ZXI7IGdhcDo0cHg7Ij4KICAgICAgICA8c3BhbiBjbGFzcz0idG9w",
  "dXAtY291bnRkb3duLWxhYmVsIj5Nw6MgUVIgaOG6v3QgaGnhu4d1IGzhu7FjIHNhdTwvc3Bhbj4K",
  "ICAgICAgICA8ZGl2IGNsYXNzPSJ0b3B1cC1jb3VudGRvd24iIGlkPSJ0b3B1cENvdW50ZG93biI+",
  "MzA6MDA8L2Rpdj4KICAgICAgPC9kaXY+CgogICAgICA8ZGl2IGNsYXNzPSJtb2RhbC1lcnJvciIg",
  "aWQ9InRvcHVwUXJFcnJvciI+PC9kaXY+CiAgICAgIDxwIGNsYXNzPSJtb2RhbC1ub3RlIj5Zw6p1",
  "IGPhuqd1IG7DoHkgc+G6vSB04buxIMSR4buZbmcgaOG6v3QgaOG6oW4gc2F1IDMwIHBow7p0IG7h",
  "ur91IHF14bqjbiB0cuG7iyB2acOqbiBjaMawYSB4w6FjIG5o4bqtbi4gQuG6oW4gY8OzIHRo4buD",
  "IHRoZW8gZMO1aSB0cuG6oW5nIHRow6FpIOG7nyBt4bulYyAiTOG7i2NoIHPhu60gbuG6oXAgdGnh",
  "u4FuIi48L3A+CgogICAgICA8ZGl2IGNsYXNzPSJtb2RhbC1hY3Rpb25zIj4KICAgICAgICA8YnV0",
  "dG9uIGNsYXNzPSJidG4gYnRuLWdob3N0IiBpZD0iYnRuQ2xvc2VUb3B1cFFyIiBzdHlsZT0id2lk",
  "dGg6MTAwJTsiPsSQw7NuZzwvYnV0dG9uPgogICAgICA8L2Rpdj4KICAgIDwvZGl2PgoKICAgIDwh",
  "LS0gVHLhuqFuZyB0aMOhaTogbcOjIFFSIMSRw6MgaOG6v3QgaOG6oW4sIGLhuq90IGJ14buZYyB0",
  "4bqhbyB5w6p1IGPhuqd1IG3hu5tpIC0tPgogICAgPGRpdiBjbGFzcz0idG9wdXAtZXhwaXJlZC1i",
  "b3giIGlkPSJ0b3B1cEV4cGlyZWRCb3giPgogICAgICA8ZGl2IGNsYXNzPSJpY29uIj4KICAgICAg",
  "ICA8c3ZnIHdpZHRoPSIyMiIgaGVpZ2h0PSIyMiIgdmlld0JveD0iMCAwIDI0IDI0IiBmaWxsPSJu",
  "b25lIiBzdHJva2U9ImN1cnJlbnRDb2xvciIgc3Ryb2tlLXdpZHRoPSIyIj48Y2lyY2xlIGN4PSIx",
  "MiIgY3k9IjEyIiByPSIxMCI+PC9jaXJjbGU+PGxpbmUgeDE9IjEyIiB5MT0iOCIgeDI9IjEyIiB5",
  "Mj0iMTIiPjwvbGluZT48bGluZSB4MT0iMTIiIHkxPSIxNiIgeDI9IjEyLjAxIiB5Mj0iMTYiPjwv",
  "bGluZT48L3N2Zz4KICAgICAgPC9kaXY+CiAgICAgIDxkaXY+CiAgICAgICAgPGgzIHN0eWxlPSJt",
  "YXJnaW4tYm90dG9tOjZweDsiPk3DoyBRUiDEkcOjIGjhur90IGhp4buHdSBs4buxYzwvaDM+CiAg",
  "ICAgICAgPHAgY2xhc3M9InN1YiIgc3R5bGU9Im1hcmdpbjowOyI+WcOqdSBj4bqndSBu4bqhcCB0",
  "aeG7gW4gbsOgeSDEkcOjIHF1w6EgMzAgcGjDunQgdsOgIHThu7EgxJHhu5luZyBi4buLIGjhu6d5",
  "LiBWdWkgbMOybmcgdOG6oW8gecOqdSBj4bqndSBu4bqhcCB0aeG7gW4gbeG7m2kuPC9wPgogICAg",
  "ICA8L2Rpdj4KICAgICAgPGRpdiBjbGFzcz0ibW9kYWwtYWN0aW9ucyIgc3R5bGU9IndpZHRoOjEw",
  "MCU7Ij4KICAgICAgICA8YnV0dG9uIGNsYXNzPSJidG4gYnRuLWdob3N0IiBpZD0iYnRuQ2xvc2VU",
  "b3B1cEV4cGlyZWQiPsSQw7NuZzwvYnV0dG9uPgogICAgICAgIDxidXR0b24gY2xhc3M9ImJ0biIg",
  "aWQ9ImJ0blJlc3RhcnRUb3B1cCI+VOG6oW8gecOqdSBj4bqndSBt4bubaTwvYnV0dG9uPgogICAg",
  "ICA8L2Rpdj4KICAgIDwvZGl2PgoKICA8L2Rpdj4KPC9kaXY+Cgo8IS0tID09PT09PT09PT09PSBN",
  "T0RBTDogTOG7ikNIIFPhu6wgTuG6oFAgVEnhu4BOID09PT09PT09PT09PSAtLT4KPGRpdiBjbGFz",
  "cz0ibW9kYWwtYmciIGlkPSJ0b3B1cEhpc3RvcnlNb2RhbEJnIj4KICA8ZGl2IGNsYXNzPSJtb2Rh",
  "bCI+CiAgICA8aDM+TOG7i2NoIHPhu60gbuG6oXAgdGnhu4FuPC9oMz4KICAgIDxwIGNsYXNzPSJz",
  "dWIiPkRhbmggc8OhY2ggY8OhYyB5w6p1IGPhuqd1IG7huqFwIHRp4buBbiDEkcOjIGfhu61pLjwv",
  "cD4KICAgIDxkaXYgY2xhc3M9Imhpc3RvcnktbGlzdCIgaWQ9InRvcHVwSGlzdG9yeUxpc3QiPjwv",
  "ZGl2PgogICAgPGRpdiBjbGFzcz0ibW9kYWwtYWN0aW9ucyI+CiAgICAgIDxidXR0b24gY2xhc3M9",
  "ImJ0biBidG4tZ2hvc3QiIGlkPSJidG5DbG9zZVRvcHVwSGlzdG9yeSIgc3R5bGU9IndpZHRoOjEw",
  "MCU7Ij7EkMOzbmc8L2J1dHRvbj4KICAgIDwvZGl2PgogIDwvZGl2Pgo8L2Rpdj4KCjwhLS0gPT09",
  "PT09PT09PT09IE1PREFMOiBM4buKQ0ggU+G7rCBHSUFPIEThu4pDSCA9PT09PT09PT09PT0gLS0+",
  "CjxkaXYgY2xhc3M9Im1vZGFsLWJnIiBpZD0idHhIaXN0b3J5TW9kYWxCZyI+CiAgPGRpdiBjbGFz",
  "cz0ibW9kYWwiPgogICAgPGgzPkzhu4tjaCBz4butIGdpYW8gZOG7i2NoPC9oMz4KICAgIDxwIGNs",
  "YXNzPSJzdWIiPlRvw6BuIGLhu5kgZ2lhbyBk4buLY2ggY+G7mW5nL3Ry4burIHRp4buBbiB2w6Ag",
  "bXVhIGtleSB0csOqbiB0w6BpIGtob+G6o24gY+G7p2EgYuG6oW4uPC9wPgogICAgPGRpdiBjbGFz",
  "cz0iaGlzdG9yeS1saXN0IiBpZD0idHhIaXN0b3J5TGlzdCI+PC9kaXY+CiAgICA8ZGl2IGNsYXNz",
  "PSJtb2RhbC1hY3Rpb25zIj4KICAgICAgPGJ1dHRvbiBjbGFzcz0iYnRuIGJ0bi1naG9zdCIgaWQ9",
  "ImJ0bkNsb3NlVHhIaXN0b3J5IiBzdHlsZT0id2lkdGg6MTAwJTsiPsSQw7NuZzwvYnV0dG9uPgog",
  "ICAgPC9kaXY+CiAgPC9kaXY+CjwvZGl2PgoKPCEtLSA9PT09PT09PT09PT0gTU9EQUw6IFFV4bqi",
  "TiBMw50gS0VZIChrZXkgxJHDoyBtdWEpID09PT09PT09PT09PSAtLT4KPGRpdiBjbGFzcz0ibW9k",
  "YWwtYmciIGlkPSJteUtleXNNb2RhbEJnIj4KICA8ZGl2IGNsYXNzPSJtb2RhbCIgc3R5bGU9Im1h",
  "eC13aWR0aDo1MjBweDsiPgogICAgPGgzPlF14bqjbiBsw70ga2V5PC9oMz4KICAgIDxwIGNsYXNz",
  "PSJzdWIiPkRhbmggc8OhY2ggY8OhYyBrZXkgYuG6oW4gxJHDoyBtdWEgdHLDqm4gdMOgaSBraG/h",
  "uqNuIG7DoHkuPC9wPgogICAgPGRpdiBjbGFzcz0iaGlzdG9yeS1saXN0IiBpZD0ibXlLZXlzTGlz",
  "dCIgc3R5bGU9Im1heC1oZWlnaHQ6NDIwcHg7Ij48L2Rpdj4KICAgIDxkaXYgY2xhc3M9Im1vZGFs",
  "LWFjdGlvbnMiPgogICAgICA8YnV0dG9uIGNsYXNzPSJidG4gYnRuLWdob3N0IiBpZD0iYnRuQ2xv",
  "c2VNeUtleXMiIHN0eWxlPSJ3aWR0aDoxMDAlOyI+xJDDs25nPC9idXR0b24+CiAgICA8L2Rpdj4K",
  "ICA8L2Rpdj4KPC9kaXY+Cgo8IS0tID09PT09PT09PT09PSBNT0RBTDogR0VUS0VZIC0gQ0jhu4xO",
  "IEdBTUUgPT09PT09PT09PT09IC0tPgo8ZGl2IGNsYXNzPSJtb2RhbC1iZyIgaWQ9ImdrQ2hvb3Nl",
  "R2FtZU1vZGFsQmciPgogIDxkaXYgY2xhc3M9Im1vZGFsIj4KICAgIDxoMz5HZXRLZXkg4oCUIFbG",
  "sOG7o3QgbGluayBuaOG6rW4ga2V5PC9oMz4KICAgIDxwIGNsYXNzPSJzdWIiPkNo4buNbiBnYW1l",
  "IGLhuqFuIG114buRbiBuaOG6rW4ga2V5LjwvcD4KICAgIDxkaXYgY2xhc3M9ImdrLWdhbWUtZ3Jp",
  "ZCIgaWQ9ImdrR2FtZUdyaWQiPjwvZGl2PgogICAgPGRpdiBjbGFzcz0iZW1wdHktc3RhdGUiIGlk",
  "PSJna0dhbWVFbXB0eVN0YXRlIiBzdHlsZT0iZGlzcGxheTpub25lOyBtYXJnaW4tdG9wOjEycHg7",
  "IHBhZGRpbmc6MzBweCAxNXB4OyI+CiAgICAgIDxkaXYgY2xhc3M9ImJpZyI+SGnhu4duIGNoxrBh",
  "IGPDsyBnYW1lIEdldEtleSBuw6BvPC9kaXY+CiAgICAgIFF14bqjbiB0cuG7iyB2acOqbiBjaMaw",
  "YSB0aMOqbSBnYW1lIG7DoG8uIFZ1aSBsw7JuZyBxdWF5IGzhuqFpIHNhdS4KICAgIDwvZGl2Pgog",
  "ICAgPGRpdiBjbGFzcz0ibW9kYWwtYWN0aW9ucyI+CiAgICAgIDxidXR0b24gY2xhc3M9ImJ0biBi",
  "dG4tZ2hvc3QiIGlkPSJidG5DbG9zZUdrQ2hvb3NlR2FtZSIgc3R5bGU9IndpZHRoOjEwMCU7Ij7E",
  "kMOzbmc8L2J1dHRvbj4KICAgIDwvZGl2PgogIDwvZGl2Pgo8L2Rpdj4KCjwhLS0gPT09PT09PT09",
  "PT09IE1PREFMOiBHRVRLRVkgLSBDSOG7jE4gVEjhu5xJIEjhuqBOID09PT09PT09PT09PSAtLT4K",
  "PGRpdiBjbGFzcz0ibW9kYWwtYmciIGlkPSJna0Nob29zZUR1cmF0aW9uTW9kYWxCZyI+CiAgPGRp",
  "diBjbGFzcz0ibW9kYWwiPgogICAgPGgzIGlkPSJna0R1cmF0aW9uR2FtZU5hbWUiPuKAlDwvaDM+",
  "CiAgICA8cCBjbGFzcz0ic3ViIj5DaOG7jW4gbG/huqFpIGtleSBi4bqhbiBtdeG7kW4gbmjhuq1u",
  "LiBUaOG7nWkgaOG6oW4gY8OgbmcgZMOgaSwgc+G7kSBsxrDhu6N0IHbGsOG7o3QgbGluayBjw6Bu",
  "ZyBuaGnhu4F1LjwvcD4KICAgIDxkaXYgY2xhc3M9ImdrLWR1cmF0aW9uLWxpc3QiIGlkPSJna0R1",
  "cmF0aW9uTGlzdFB1YmxpYyI+PC9kaXY+CiAgICA8ZGl2IGNsYXNzPSJtb2RhbC1lcnJvciIgaWQ9",
  "ImdrRHVyYXRpb25FcnJvciI+PC9kaXY+CiAgICA8ZGl2IGNsYXNzPSJtb2RhbC1hY3Rpb25zIj4K",
  "ICAgICAgPGJ1dHRvbiBjbGFzcz0iYnRuIGJ0bi1naG9zdCIgaWQ9ImJ0bkJhY2tHa0R1cmF0aW9u",
  "Ij5RdWF5IGzhuqFpPC9idXR0b24+CiAgICAgIDxidXR0b24gY2xhc3M9ImJ0biIgaWQ9ImJ0blN0",
  "YXJ0R2tGbG93Ij5C4bqvdCDEkeG6p3Ugdsaw4bujdCBsaW5rPC9idXR0b24+CiAgICA8L2Rpdj4K",
  "ICA8L2Rpdj4KPC9kaXY+Cgo8IS0tID09PT09PT09PT09PSBNT0RBTDogR0VUS0VZIC0gVsav4bui",
  "VCBMSU5LID09PT09PT09PT09PSAtLT4KPGRpdiBjbGFzcz0ibW9kYWwtYmciIGlkPSJna0Zsb3dN",
  "b2RhbEJnIj4KICA8ZGl2IGNsYXNzPSJtb2RhbCI+CiAgICA8aDM+xJBhbmcgdsaw4bujdCBsaW5r",
  "IG5o4bqtbiBrZXk8L2gzPgogICAgPHAgY2xhc3M9InN1YiIgaWQ9ImdrRmxvd0dhbWVMYWJlbCI+",
  "4oCUPC9wPgogICAgPGRpdiBjbGFzcz0iZ2stcHJvZ3Jlc3MiIGlkPSJna1Byb2dyZXNzRG90cyI+",
  "PC9kaXY+CiAgICA8ZGl2IGNsYXNzPSJnay1zdGVwLWJveCI+CiAgICAgIDxkaXYgY2xhc3M9InJv",
  "dW5kLWxhYmVsIiBpZD0iZ2tSb3VuZExhYmVsIj5MxrDhu6N0IDE8L2Rpdj4KICAgICAgPGEgaHJl",
  "Zj0iIyIgdGFyZ2V0PSJfYmxhbmsiIHJlbD0ibm9vcGVuZXIiIGNsYXNzPSJidG4iIGlkPSJidG5P",
  "cGVuR2tMaW5rIiBzdHlsZT0id2lkdGg6MTAwJTsgZGlzcGxheTppbmxpbmUtYmxvY2s7IHRleHQt",
  "YWxpZ246Y2VudGVyOyB0ZXh0LWRlY29yYXRpb246bm9uZTsiPk3hu58gbGluayB2xrDhu6N0IChs",
  "xrDhu6N0IDEpPC9hPgogICAgPC9kaXY+CiAgICA8cCBjbGFzcz0ibW9kYWwtbm90ZSI+U2F1IGto",
  "aSBt4bufIGxpbmsgdsOgIGhvw6BuIHRow6BuaCB0cmFuZyDEkcOtY2gsIHF1YXkgbOG6oWkgxJHD",
  "onkgdsOgIGLhuqVtICJUw7RpIMSRw6Mgdsaw4bujdCBsaW5rIiDEkeG7gyB0aeG6v3AgdOG7pWMu",
  "PC9wPgogICAgPGRpdiBjbGFzcz0ibW9kYWwtZXJyb3IiIGlkPSJna0Zsb3dFcnJvciI+PC9kaXY+",
  "CiAgICA8ZGl2IGNsYXNzPSJtb2RhbC1hY3Rpb25zIj4KICAgICAgPGJ1dHRvbiBjbGFzcz0iYnRu",
  "IGJ0bi1naG9zdCIgaWQ9ImJ0bkNsb3NlR2tGbG93Ij5IdeG7tzwvYnV0dG9uPgogICAgICA8YnV0",
  "dG9uIGNsYXNzPSJidG4iIGlkPSJidG5Db25maXJtR2tTdGVwIj5Uw7RpIMSRw6Mgdsaw4bujdCBs",
  "aW5rPC9idXR0b24+CiAgICA8L2Rpdj4KICA8L2Rpdj4KPC9kaXY+Cgo8IS0tID09PT09PT09PT09",
  "PSBNT0RBTDogR0VUS0VZIC0gS+G6vlQgUVXhuqIgPT09PT09PT09PT09IC0tPgo8ZGl2IGNsYXNz",
  "PSJtb2RhbC1iZyIgaWQ9ImdrUmVzdWx0TW9kYWxCZyI+CiAgPGRpdiBjbGFzcz0ibW9kYWwiPgog",
  "ICAgPGgzPvCfjokgTmjhuq1uIGtleSB0aMOgbmggY8O0bmchPC9oMz4KICAgIDxwIGNsYXNzPSJz",
  "dWIiPktleSBj4bunYSBi4bqhbiDEkcOjIHPhurVuIHPDoG5nLCB2dWkgbMOybmcgbMawdSBs4bqh",
  "aSBj4bqpbiB0aOG6rW4uPC9wPgogICAgPGRpdiBjbGFzcz0icmVzdWx0LWtleS1ib3giPgogICAg",
  "ICA8Y29kZSBpZD0iZ2tSZXN1bHRLZXlWYWx1ZSI+4oCUPC9jb2RlPgogICAgICA8YnV0dG9uIGNs",
  "YXNzPSJidG4iIGlkPSJidG5Db3B5R2tSZXN1bHRLZXkiIHN0eWxlPSJ3aWR0aDoxMDAlOyI+U2Fv",
  "IGNow6lwIGtleTwvYnV0dG9uPgogICAgPC9kaXY+CiAgICA8ZGl2IGNsYXNzPSJtb2RhbC1hY3Rp",
  "b25zIj4KICAgICAgPGJ1dHRvbiBjbGFzcz0iYnRuIGJ0bi1naG9zdCIgaWQ9ImJ0bkNsb3NlR2tS",
  "ZXN1bHQiIHN0eWxlPSJ3aWR0aDoxMDAlOyI+xJDDs25nPC9idXR0b24+CiAgICA8L2Rpdj4KICA8",
  "L2Rpdj4KPC9kaXY+Cgo8ZGl2IGNsYXNzPSJ0b2FzdCIgaWQ9InRvYXN0Ij48L2Rpdj4KCjxzY3Jp",
  "cHQ+CmNvbnN0IEFQSV9CQVNFID0gJyc7IC8vIGPDuW5nIGRvbWFpbiB24bubaSB0cmFuZyBuw6B5",
  "CgovKiAtLS0tLS0tLS0tIEhlbHBlciAtLS0tLS0tLS0tICovCmZ1bmN0aW9uICQoaWQpeyByZXR1",
  "cm4gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoaWQpOyB9CmZ1bmN0aW9uIGZtdE1vbmV5KHYpewog",
  "IGNvbnN0IG4gPSBwYXJzZUZsb2F0KFN0cmluZyh2KS5yZXBsYWNlKC9bXlxkLl0vZywnJykpOwog",
  "IGlmKCFuICYmIG4hPT0wKSByZXR1cm4gJzDigqsnOwogIHJldHVybiBuLnRvTG9jYWxlU3RyaW5n",
  "KCd2aS1WTicpKyfigqsnOwp9CmZ1bmN0aW9uIHNob3dUb2FzdChtc2cpewogIGNvbnN0IHQgPSAk",
  "KCd0b2FzdCcpOwogIHQudGV4dENvbnRlbnQgPSBtc2c7CiAgdC5jbGFzc0xpc3QuYWRkKCdzaG93",
  "Jyk7CiAgY2xlYXJUaW1lb3V0KHNob3dUb2FzdC5fdGltZXIpOwogIHNob3dUb2FzdC5fdGltZXIg",
  "PSBzZXRUaW1lb3V0KCgpPT4gdC5jbGFzc0xpc3QucmVtb3ZlKCdzaG93JyksIDMyMDApOwp9Cgov",
  "KiAtLS0tLS0tLS0tIFRy4bqhbmcgdGjDoWkgxJHEg25nIG5o4bqtcCBraMOhY2ggaMOgbmcgLS0t",
  "LS0tLS0tLSAqLwpsZXQgY3VzdG9tZXJUb2tlbiA9IGxvY2FsU3RvcmFnZS5nZXRJdGVtKCdrdl9z",
  "dG9yZV90b2tlbicpIHx8ICcnOwpsZXQgY3VzdG9tZXJOYW1lID0gbG9jYWxTdG9yYWdlLmdldEl0",
  "ZW0oJ2t2X3N0b3JlX3VzZXJuYW1lJykgfHwgJyc7CmxldCBjdXN0b21lckJhbGFuY2UgPSAwOwps",
  "ZXQgY3VzdG9tZXJSb2xlID0gJ2N1c3RvbWVyJzsKCmZ1bmN0aW9uIHVwZGF0ZUFjY291bnRVSSgp",
  "ewogIGlmKGN1c3RvbWVyVG9rZW4gJiYgY3VzdG9tZXJOYW1lKXsKICAgICQoJ2d1ZXN0QWN0aW9u",
  "cycpLnN0eWxlLmRpc3BsYXkgPSAnbm9uZSc7CiAgICAkKCdhY2NvdW50Q2hpcCcpLnN0eWxlLmRp",
  "c3BsYXkgPSAnZmxleCc7CiAgICAkKCdhY2NvdW50TmFtZScpLnRleHRDb250ZW50ID0gY3VzdG9t",
  "ZXJOYW1lOwogICAgJCgnZGRHdWVzdEJsb2NrJykuc3R5bGUuZGlzcGxheSA9ICdub25lJzsKICAg",
  "ICQoJ2RkQWNjb3VudEJsb2NrJykuc3R5bGUuZGlzcGxheSA9ICcnOwogICAgJCgnZGRBY2NvdW50",
  "TmFtZScpLnRleHRDb250ZW50ID0gY3VzdG9tZXJOYW1lOwogICAgJCgnZGRBY2NvdW50QmFsYW5j",
  "ZScpLnRleHRDb250ZW50ID0gZm10TW9uZXkoY3VzdG9tZXJCYWxhbmNlKTsKICB9IGVsc2Ugewog",
  "ICAgJCgnZ3Vlc3RBY3Rpb25zJykuc3R5bGUuZGlzcGxheSA9ICcnOwogICAgJCgnYWNjb3VudENo",
  "aXAnKS5zdHlsZS5kaXNwbGF5ID0gJ25vbmUnOwogICAgJCgnZGRHdWVzdEJsb2NrJykuc3R5bGUu",
  "ZGlzcGxheSA9ICcnOwogICAgJCgnZGRBY2NvdW50QmxvY2snKS5zdHlsZS5kaXNwbGF5ID0gJ25v",
  "bmUnOwogIH0KfQp1cGRhdGVBY2NvdW50VUkoKTsKCi8qIE7hur91IMSRw6MgY8OzIHRva2VuIGzG",
  "sHUgc+G6tW4gKMSRxINuZyBuaOG6rXAgdOG7qyB0csaw4bubYyksIHThuqNpIGzhuqFpIHPhu5Eg",
  "ZMawIG3hu5tpIG5o4bqldCB04burIHNlcnZlciAqLwphc3luYyBmdW5jdGlvbiByZWZyZXNoQ3Vz",
  "dG9tZXJQcm9maWxlKCl7CiAgaWYoIWN1c3RvbWVyVG9rZW4pIHJldHVybjsKICB0cnl7CiAgICBj",
  "b25zdCByZXMgPSBhd2FpdCBmZXRjaChBUElfQkFTRSArICcvYXBpL2F1dGgvbWUnLCB7IGhlYWRl",
  "cnM6eyAnQXV0aG9yaXphdGlvbic6ICdCZWFyZXIgJyArIGN1c3RvbWVyVG9rZW4gfSB9KTsKICAg",
  "IGlmKCFyZXMub2speyB0aHJvdyBuZXcgRXJyb3IoJ3Rva2VuIGludmFsaWQnKTsgfQogICAgY29u",
  "c3QgZGF0YSA9IGF3YWl0IHJlcy5qc29uKCk7CiAgICBpZihkYXRhLm9rKXsKICAgICAgY3VzdG9t",
  "ZXJCYWxhbmNlID0gZGF0YS5iYWxhbmNlIHx8IDA7CiAgICAgIGN1c3RvbWVyUm9sZSA9IGRhdGEu",
  "cm9sZSB8fCAnY3VzdG9tZXInOwogICAgICB1cGRhdGVBY2NvdW50VUkoKTsKICAgIH0KICB9Y2F0",
  "Y2goZSl7CiAgICAvLyB0b2tlbiBo4bq/dCBo4bqhbi9raMO0bmcgaOG7o3AgbOG7hyAtPiDEkcSD",
  "bmcgeHXhuqV0IMOqbSwga2jDtG5nIGzDoG0gcGhp4buBbiBraMOhY2ggYuG6sW5nIGzhu5dpCiAg",
  "ICBjdXN0b21lclRva2VuID0gJyc7IGN1c3RvbWVyTmFtZSA9ICcnOwogICAgbG9jYWxTdG9yYWdl",
  "LnJlbW92ZUl0ZW0oJ2t2X3N0b3JlX3Rva2VuJyk7CiAgICBsb2NhbFN0b3JhZ2UucmVtb3ZlSXRl",
  "bSgna3Zfc3RvcmVfdXNlcm5hbWUnKTsKICAgIHVwZGF0ZUFjY291bnRVSSgpOwogIH0KfQpyZWZy",
  "ZXNoQ3VzdG9tZXJQcm9maWxlKCk7CgokKCdidG5Mb2dvdXRDdXN0b21lcicpLmFkZEV2ZW50TGlz",
  "dGVuZXIoJ2NsaWNrJywgKCk9PnsKICBjdXN0b21lclRva2VuID0gJyc7IGN1c3RvbWVyTmFtZSA9",
  "ICcnOyBjdXN0b21lckJhbGFuY2UgPSAwOyBjdXN0b21lclJvbGUgPSAnY3VzdG9tZXInOwogIGxv",
  "Y2FsU3RvcmFnZS5yZW1vdmVJdGVtKCdrdl9zdG9yZV90b2tlbicpOwogIGxvY2FsU3RvcmFnZS5y",
  "ZW1vdmVJdGVtKCdrdl9zdG9yZV91c2VybmFtZScpOwogIHVwZGF0ZUFjY291bnRVSSgpOwogIGNs",
  "b3NlRHJvcGRvd24oKTsKICBzaG93VG9hc3QoJ8SQw6MgxJHEg25nIHh14bqldCcpOwp9KTsKCi8q",
  "IC0tLS0tLS0tLS0gTWVudSAzIGfhuqFjaCAoaGFtYnVyZ2VyIGRyb3Bkb3duKSAtLS0tLS0tLS0t",
  "ICovCmZ1bmN0aW9uIG9wZW5Ecm9wZG93bigpeyAkKCdkcm9wZG93bk1lbnUnKS5jbGFzc0xpc3Qu",
  "YWRkKCdzaG93Jyk7IH0KZnVuY3Rpb24gY2xvc2VEcm9wZG93bigpeyAkKCdkcm9wZG93bk1lbnUn",
  "KS5jbGFzc0xpc3QucmVtb3ZlKCdzaG93Jyk7IH0KJCgnYnRuSGFtYnVyZ2VyJykuYWRkRXZlbnRM",
  "aXN0ZW5lcignY2xpY2snLCAoZSk9PnsKICBlLnN0b3BQcm9wYWdhdGlvbigpOwogICQoJ2Ryb3Bk",
  "b3duTWVudScpLmNsYXNzTGlzdC50b2dnbGUoJ3Nob3cnKTsKfSk7CmRvY3VtZW50LmFkZEV2ZW50",
  "TGlzdGVuZXIoJ2NsaWNrJywgKGUpPT57CiAgaWYoISQoJ2Ryb3Bkb3duTWVudScpLmNvbnRhaW5z",
  "KGUudGFyZ2V0KSAmJiBlLnRhcmdldCAhPT0gJCgnYnRuSGFtYnVyZ2VyJykpewogICAgY2xvc2VE",
  "cm9wZG93bigpOwogIH0KfSk7CgokKCdkZE9wZW5BdXRoJykuYWRkRXZlbnRMaXN0ZW5lcignY2xp",
  "Y2snLCAoKT0+eyBjbG9zZURyb3Bkb3duKCk7IG9wZW5BdXRoTW9kYWwoKTsgfSk7CgokKCdkZFN1",
  "cHBvcnQnKS5hZGRFdmVudExpc3RlbmVyKCdjbGljaycsICgpPT57CiAgY2xvc2VEcm9wZG93bigp",
  "OwogIHdpbmRvdy5vcGVuKCdodHRwczovL3QubWUvbHVvbmd0dXllbjIwJywgJ19ibGFuaycpOwp9",
  "KTsKCiQoJ2RkQWNjb3VudEluZm8nKS5hZGRFdmVudExpc3RlbmVyKCdjbGljaycsICgpPT57CiAg",
  "Y2xvc2VEcm9wZG93bigpOwogICQoJ2luZm9Vc2VybmFtZScpLnRleHRDb250ZW50ID0gY3VzdG9t",
  "ZXJOYW1lOwogICQoJ2luZm9CYWxhbmNlJykudGV4dENvbnRlbnQgPSBmbXRNb25leShjdXN0b21l",
  "ckJhbGFuY2UpOwogICQoJ2luZm9Sb2xlJykudGV4dENvbnRlbnQgPSBjdXN0b21lclJvbGUgPT09",
  "ICdhZG1pbicgPyAnUXXhuqNuIHRy4buLIHZpw6puJyA6ICdLaMOhY2ggaMOgbmcnOwogICQoJ2Fj",
  "Y291bnRJbmZvTW9kYWxCZycpLmNsYXNzTGlzdC5hZGQoJ3Nob3cnKTsKfSk7CiQoJ2J0bkNsb3Nl",
  "QWNjb3VudEluZm8nKS5hZGRFdmVudExpc3RlbmVyKCdjbGljaycsICgpPT4gJCgnYWNjb3VudElu",
  "Zm9Nb2RhbEJnJykuY2xhc3NMaXN0LnJlbW92ZSgnc2hvdycpKTsKCi8qIC0tLS0gTuG6oXAgdGnh",
  "u4FuIHThu7EgxJHhu5luZzogYsaw4bubYyAxIChuaOG6rXAgc+G7kSB0aeG7gW4pIC0+IGLGsOG7",
  "m2MgMiAoUVIgxJHhu5luZyArIMSR4bq/bSBuZ8aw4bujYyAzMCBwaMO6dCkgLS0tLQogICDEkOG7",
  "k25nIGjhu5MgxJHhur9tIG5nxrDhu6NjIGNo4bqheSDhu58gY2xpZW50IGThu7FhIHRyw6puICJl",
  "eHBpcmVzQXQiIGRvIFNFUlZFUiB0cuG6oyB24buBIChraMO0bmcgdOG7sSB0w61uaAogICAzMCBw",
  "aMO6dCB04burIGzDumMgYuG6pW0gbsO6dCDhu58gY2xpZW50KSwgbsOqbiBsdcO0biBraOG7m3Ag",
  "duG7m2kgaOG6oW4gdGjhuq10IGzGsHUgdHJvbmcgZGF0YWJhc2UsIHRyw6FuaAogICB0csaw4bud",
  "bmcgaOG7o3AgbOG7h2NoIGdp4budIG3DoXkga2jDoWNoIGjDoG5nLiAqLwpsZXQgdG9wdXBDb3Vu",
  "dGRvd25UaW1lciA9IG51bGw7CmxldCB0b3B1cFBvbGxUaW1lciA9IG51bGw7CmxldCBjdXJyZW50",
  "VG9wdXBSZXF1ZXN0SWQgPSBudWxsOwoKZnVuY3Rpb24gc2hvd1RvcHVwU3RlcChzdGVwKXsKICAk",
  "KCd0b3B1cFN0ZXBBbW91bnQnKS5zdHlsZS5kaXNwbGF5ID0gc3RlcCA9PT0gJ2Ftb3VudCcgPyAn",
  "ZmxleCcgOiAnbm9uZSc7CiAgJCgndG9wdXBTdGVwUXInKS5zdHlsZS5kaXNwbGF5ID0gc3RlcCA9",
  "PT0gJ3FyJyA/ICdmbGV4JyA6ICdub25lJzsKICAkKCd0b3B1cEV4cGlyZWRCb3gnKS5zdHlsZS5k",
  "aXNwbGF5ID0gc3RlcCA9PT0gJ2V4cGlyZWQnID8gJ2ZsZXgnIDogJ25vbmUnOwp9CgpmdW5jdGlv",
  "biBzdG9wVG9wdXBUaW1lcnMoKXsKICBpZih0b3B1cENvdW50ZG93blRpbWVyKXsgY2xlYXJJbnRl",
  "cnZhbCh0b3B1cENvdW50ZG93blRpbWVyKTsgdG9wdXBDb3VudGRvd25UaW1lciA9IG51bGw7IH0K",
  "ICBpZih0b3B1cFBvbGxUaW1lcil7IGNsZWFySW50ZXJ2YWwodG9wdXBQb2xsVGltZXIpOyB0b3B1",
  "cFBvbGxUaW1lciA9IG51bGw7IH0KfQoKZnVuY3Rpb24gb3BlblRvcHVwRXhwaXJlZCgpewogIHN0",
  "b3BUb3B1cFRpbWVycygpOwogIHNob3dUb3B1cFN0ZXAoJ2V4cGlyZWQnKTsKfQoKZnVuY3Rpb24g",
  "c3RhcnRUb3B1cENvdW50ZG93bihleHBpcmVzQXRJc28pewogIGNvbnN0IGV4cGlyZXNBdE1zID0g",
  "bmV3IERhdGUoZXhwaXJlc0F0SXNvKS5nZXRUaW1lKCk7CiAgY29uc3QgZWwgPSAkKCd0b3B1cENv",
  "dW50ZG93bicpOwogIGZ1bmN0aW9uIHRpY2soKXsKICAgIGNvbnN0IHJlbWFpbk1zID0gZXhwaXJl",
  "c0F0TXMgLSBEYXRlLm5vdygpOwogICAgaWYocmVtYWluTXMgPD0gMCl7CiAgICAgIG9wZW5Ub3B1",
  "cEV4cGlyZWQoKTsKICAgICAgcmV0dXJuOwogICAgfQogICAgY29uc3QgdG90YWxTZWMgPSBNYXRo",
  "LmZsb29yKHJlbWFpbk1zIC8gMTAwMCk7CiAgICBjb25zdCBtbSA9IE1hdGguZmxvb3IodG90YWxT",
  "ZWMgLyA2MCkudG9TdHJpbmcoKS5wYWRTdGFydCgyLCAnMCcpOwogICAgY29uc3Qgc3MgPSAodG90",
  "YWxTZWMgJSA2MCkudG9TdHJpbmcoKS5wYWRTdGFydCgyLCAnMCcpOwogICAgZWwudGV4dENvbnRl",
  "bnQgPSBtbSArICc6JyArIHNzOwogICAgZWwuY2xhc3NMaXN0LnRvZ2dsZSgnd2FybicsIHRvdGFs",
  "U2VjIDw9IDYwKTsgLy8gxJHhu5VpIG3DoHUgY+G6o25oIGLDoW8ga2hpIGPDsm4gZMaw4bubaSAx",
  "IHBow7p0CiAgfQogIHRpY2soKTsKICB0b3B1cENvdW50ZG93blRpbWVyID0gc2V0SW50ZXJ2YWwo",
  "dGljaywgMTAwMCk7Cn0KCi8qIMSQ4buTbmcgYuG7mSB0cuG6oW5nIHRow6FpIHbhu5tpIHNlcnZl",
  "ciBt4buXaSAxMCBnacOieTogbuG6v3UgYWRtaW4gxJHDoyBkdXnhu4d0L3Thu6sgY2jhu5FpLCBo",
  "b+G6t2Mgc2VydmVyIHThu7EKICAgxJHDoW5oIGThuqV1IGjhur90IGjhuqFuICh0csaw4budbmcg",
  "aOG7o3AgY2xpZW50IG3huqV0IG3huqFuZy/EkeG7lWkgdGFiIGzDonUpLCBj4bqtcCBuaOG6rXQg",
  "VUkgdMawxqFuZyDhu6luZyBuZ2F5LiAqLwpmdW5jdGlvbiBzdGFydFRvcHVwU3RhdHVzUG9sbGlu",
  "ZyhyZXF1ZXN0SWQpewogIHRvcHVwUG9sbFRpbWVyID0gc2V0SW50ZXJ2YWwoYXN5bmMgKCk9PnsK",
  "ICAgIHRyeXsKICAgICAgY29uc3QgcmVzID0gYXdhaXQgZmV0Y2goQVBJX0JBU0UgKyAnL2FwaS90",
  "b3B1cC1yZXF1ZXN0LycgKyByZXF1ZXN0SWQsIHsKICAgICAgICBoZWFkZXJzOnsgJ0F1dGhvcml6",
  "YXRpb24nOiAnQmVhcmVyICcgKyBjdXN0b21lclRva2VuIH0KICAgICAgfSk7CiAgICAgIGlmKCFy",
  "ZXMub2spIHJldHVybjsKICAgICAgY29uc3QgZGF0YSA9IGF3YWl0IHJlcy5qc29uKCk7CiAgICAg",
  "IGlmKCFkYXRhLm9rIHx8ICFkYXRhLnJlcXVlc3QpIHJldHVybjsKICAgICAgY29uc3Qgc3RhdHVz",
  "ID0gZGF0YS5yZXF1ZXN0LnN0YXR1czsKICAgICAgaWYoc3RhdHVzID09PSAnZXhwaXJlZCcpewog",
  "ICAgICAgIG9wZW5Ub3B1cEV4cGlyZWQoKTsKICAgICAgfSBlbHNlIGlmKHN0YXR1cyA9PT0gJ2Fw",
  "cHJvdmVkJyl7CiAgICAgICAgc3RvcFRvcHVwVGltZXJzKCk7CiAgICAgICAgJCgndG9wdXBNb2Rh",
  "bEJnMicpLmNsYXNzTGlzdC5yZW1vdmUoJ3Nob3cnKTsKICAgICAgICAvLyBO4bq/dSDEkcaw4buj",
  "YyBkdXnhu4d0IHThu7EgxJHhu5luZyBxdWEgxJHhu5FpIHNvw6F0IGNodXnhu4NuIGtob+G6o24g",
  "KFNlUGF5KSwgaGnhu4duIHRow7RuZyBiw6FvIHBow7kgaOG7o3AKICAgICAgICAvLyBoxqFuIGzD",
  "oCAixJHGsOG7o2MgZHV54buHdCIgKG5naGUgbmjGsCBj4bqnbiB0aGFvIHTDoWMgdGjhu6cgY8O0",
  "bmcgY+G7p2EgYWRtaW4pLgogICAgICAgIGNvbnN0IGlzQXV0b0FwcHJvdmVkID0gZGF0YS5yZXF1",
  "ZXN0LmFwcHJvdmVkQnkgPT09ICdzZXBheV9hdXRvJzsKICAgICAgICBzaG93VG9hc3QoaXNBdXRv",
  "QXBwcm92ZWQKICAgICAgICAgID8gJ8SQw6Mgbmjhuq1uIMSRxrDhu6NjIGNodXnhu4NuIGtob+G6",
  "o24g4oCUIHPhu5EgZMawIMSRw6MgxJHGsOG7o2MgY+G7mW5nIHThu7EgxJHhu5luZyEnCiAgICAg",
  "ICAgICA6ICdZw6p1IGPhuqd1IG7huqFwIHRp4buBbiDEkcOjIMSRxrDhu6NjIGR1eeG7h3Qg4oCU",
  "IHPhu5EgZMawIMSRw6MgxJHGsOG7o2MgY+G7mW5nIScpOwogICAgICAgIHJlZnJlc2hDdXN0b21l",
  "ckJhbGFuY2VJZlBvc3NpYmxlKCk7CiAgICAgIH0gZWxzZSBpZihzdGF0dXMgPT09ICdyZWplY3Rl",
  "ZCcpewogICAgICAgIHN0b3BUb3B1cFRpbWVycygpOwogICAgICAgICQoJ3RvcHVwTW9kYWxCZzIn",
  "KS5jbGFzc0xpc3QucmVtb3ZlKCdzaG93Jyk7CiAgICAgICAgc2hvd1RvYXN0KCdZw6p1IGPhuqd1",
  "IG7huqFwIHRp4buBbiDEkcOjIGLhu4sgdOG7qyBjaOG7kWksIHZ1aSBsw7JuZyBsacOqbiBo4buH",
  "IGjhu5cgdHLhu6MnKTsKICAgICAgfQogICAgfWNhdGNoKGUpeyAvKiBs4buXaSBt4bqhbmcgdOG6",
  "oW0gdGjhu51pLCB0aOG7rSBs4bqhaSDhu58gbMaw4bujdCBwb2xsIGvhur8gdGnhur9wICovIH0K",
  "ICB9LCA0MDAwKTsgLy8gNCBnacOieS9s4bqnbiDigJQgxJHhu6cgbmhhbmggxJHhu4Mga2jDoWNo",
  "IHRo4bqleSBz4buRIGTGsCBj4buZbmcgZ+G6p24gbmjGsCBuZ2F5IHNhdSBraGkgY2h1eeG7g24g",
  "a2hv4bqjbgp9CgovKiBD4bqtcCBuaOG6rXQgbOG6oWkgc+G7kSBkxrAgaGnhu4NuIHRo4buLIHRy",
  "w6puIHRyYW5nIChu4bq/dSBjw7MgaMOgbS9iaeG6v24gdMawxqFuZyDhu6luZyksIGfhu41pIHNh",
  "dSBraGkgMSB5w6p1CiAgIGPhuqd1IG7huqFwIHRp4buBbiDEkcaw4bujYyBkdXnhu4d0IHRyb25n",
  "IGzDumMgbW9kYWwgxJFhbmcgbeG7nywgxJHhu4Mga2jDoWNoIHRo4bqleSBz4buRIGTGsCBt4bub",
  "aSBuZ2F5LiAqLwphc3luYyBmdW5jdGlvbiByZWZyZXNoQ3VzdG9tZXJCYWxhbmNlSWZQb3NzaWJs",
  "ZSgpewogIHRyeXsKICAgIGNvbnN0IHJlcyA9IGF3YWl0IGZldGNoKEFQSV9CQVNFICsgJy9hcGkv",
  "YXV0aC9tZScsIHsgaGVhZGVyczp7ICdBdXRob3JpemF0aW9uJzogJ0JlYXJlciAnICsgY3VzdG9t",
  "ZXJUb2tlbiB9IH0pOwogICAgaWYoIXJlcy5vaykgcmV0dXJuOwogICAgY29uc3QgZGF0YSA9IGF3",
  "YWl0IHJlcy5qc29uKCk7CiAgICBpZihkYXRhICYmIGRhdGEub2spewogICAgICBjdXN0b21lckJh",
  "bGFuY2UgPSBkYXRhLmJhbGFuY2UgfHwgMDsKICAgICAgaWYodHlwZW9mIHVwZGF0ZUFjY291bnRV",
  "SSA9PT0gJ2Z1bmN0aW9uJykgdXBkYXRlQWNjb3VudFVJKCk7CiAgICB9CiAgfWNhdGNoKGUpeyAv",
  "KiBi4buPIHF1YSwga2jDtG5nIHF1YW4gdHLhu41uZyBi4bqxbmcgdmnhu4djIHRow7RuZyBiw6Fv",
  "IMSRw6MgZHV54buHdCDhu58gdHLDqm4gKi8gfQp9CgokKCdkZFRvcHVwJykuYWRkRXZlbnRMaXN0",
  "ZW5lcignY2xpY2snLCAoKT0+ewogIGNsb3NlRHJvcGRvd24oKTsKICBzdG9wVG9wdXBUaW1lcnMo",
  "KTsKICAkKCd0b3B1cFJlcXVlc3RBbW91bnQnKS52YWx1ZSA9ICcnOwogICQoJ3RvcHVwUmVxdWVz",
  "dEVycm9yJykuY2xhc3NMaXN0LnJlbW92ZSgnc2hvdycpOwogIHNob3dUb3B1cFN0ZXAoJ2Ftb3Vu",
  "dCcpOwogICQoJ3RvcHVwTW9kYWxCZzInKS5jbGFzc0xpc3QuYWRkKCdzaG93Jyk7Cn0pOwokKCdi",
  "dG5DbG9zZVRvcHVwMicpLmFkZEV2ZW50TGlzdGVuZXIoJ2NsaWNrJywgKCk9PnsKICBzdG9wVG9w",
  "dXBUaW1lcnMoKTsKICAkKCd0b3B1cE1vZGFsQmcyJykuY2xhc3NMaXN0LnJlbW92ZSgnc2hvdycp",
  "Owp9KTsKJCgnYnRuQ2xvc2VUb3B1cFFyJykuYWRkRXZlbnRMaXN0ZW5lcignY2xpY2snLCAoKT0+",
  "ewogIC8vIMSQw7NuZyBtb2RhbCBLSMOUTkcgaOG7p3kgecOqdSBj4bqndSDigJQgecOqdSBj4bqn",
  "dSB24bqrbiDEkWFuZyBjaOG7nSBkdXnhu4d0IHRyb25nIDMwIHBow7p0LCBraMOhY2ggY8OzIHRo",
  "4buDCiAgLy8geGVtIGzhuqFpIHRy4bqhbmcgdGjDoWkg4bufICJM4buLY2ggc+G7rSBu4bqhcCB0",
  "aeG7gW4iLiBUaW1lciBjbGllbnQgZOG7q25nIGzhuqFpIHbDrCBtb2RhbCDEkcOjIMSRw7NuZy4K",
  "ICBzdG9wVG9wdXBUaW1lcnMoKTsKICAkKCd0b3B1cE1vZGFsQmcyJykuY2xhc3NMaXN0LnJlbW92",
  "ZSgnc2hvdycpOwp9KTsKJCgnYnRuQmFja1RvcHVwQW1vdW50JykuYWRkRXZlbnRMaXN0ZW5lcign",
  "Y2xpY2snLCAoKT0+ewogIC8vIMSQ4buVaSBz4buRIHRp4buBbiBraMOhYyBjb2kgbmjGsCBo4bun",
  "eSB5w6p1IGPhuqd1IGhp4buHbiB04bqhaSB24buBIG3hurd0IGhp4buDbiB0aOG7iyAoecOqdSBj",
  "4bqndSBjxakgduG6q24gY2jhu50g4bufCiAgLy8gc2VydmVyLCBjaOG7iSBo4bq/dCBo4bqhbiB0",
  "4buxIG5oacOqbiBzYXUgMzAgcGjDunQgbuG6v3Uga2jDoWNoIGtow7RuZyBxdcOpdCBRUiBu4buv",
  "YSkuCiAgc3RvcFRvcHVwVGltZXJzKCk7CiAgc2hvd1RvcHVwU3RlcCgnYW1vdW50Jyk7Cn0pOwok",
  "KCdidG5DbG9zZVRvcHVwRXhwaXJlZCcpLmFkZEV2ZW50TGlzdGVuZXIoJ2NsaWNrJywgKCk9PnsK",
  "ICAkKCd0b3B1cE1vZGFsQmcyJykuY2xhc3NMaXN0LnJlbW92ZSgnc2hvdycpOwp9KTsKJCgnYnRu",
  "UmVzdGFydFRvcHVwJykuYWRkRXZlbnRMaXN0ZW5lcignY2xpY2snLCAoKT0+ewogICQoJ3RvcHVw",
  "UmVxdWVzdEFtb3VudCcpLnZhbHVlID0gJyc7CiAgJCgndG9wdXBSZXF1ZXN0RXJyb3InKS5jbGFz",
  "c0xpc3QucmVtb3ZlKCdzaG93Jyk7CiAgc2hvd1RvcHVwU3RlcCgnYW1vdW50Jyk7Cn0pOwoKJCgn",
  "YnRuU3VibWl0VG9wdXBSZXF1ZXN0JykuYWRkRXZlbnRMaXN0ZW5lcignY2xpY2snLCBhc3luYyAo",
  "KT0+ewogIGNvbnN0IGVyckJveCA9ICQoJ3RvcHVwUmVxdWVzdEVycm9yJyk7CiAgZXJyQm94LmNs",
  "YXNzTGlzdC5yZW1vdmUoJ3Nob3cnKTsKICBjb25zdCBhbW91bnQgPSBwYXJzZUZsb2F0KCQoJ3Rv",
  "cHVwUmVxdWVzdEFtb3VudCcpLnZhbHVlLnJlcGxhY2UoL1teXGQuXS9nLCcnKSkgfHwgMDsKICBp",
  "ZihhbW91bnQgPCAxMDAwMCl7IGVyckJveC50ZXh0Q29udGVudCA9ICdT4buRIHRp4buBbiBu4bqh",
  "cCB04buRaSB0aGnhu4N1IGzDoCAxMC4wMDDigqsnOyBlcnJCb3guY2xhc3NMaXN0LmFkZCgnc2hv",
  "dycpOyByZXR1cm47IH0KICBpZihhbW91bnQgPiA1MDAwMDAwMDApeyBlcnJCb3gudGV4dENvbnRl",
  "bnQgPSAnU+G7kSB0aeG7gW4gbuG6oXAgdOG7kWkgxJFhIGzDoCA1MDAuMDAwLjAwMOKCqyc7IGVy",
  "ckJveC5jbGFzc0xpc3QuYWRkKCdzaG93Jyk7IHJldHVybjsgfQogIC8vIFnDqnUgY+G6p3UgcGjh",
  "uqNpIMSRxINuZyBuaOG6rXAgdHLGsOG7m2Mga2hpIGfhu41pIEFQSSDigJQgdHLDoW5oIGfhu41p",
  "IEFQSSBy4buTaSBt4bubaSBuaOG6rW4gbOG7l2kgbcahIGjhu5MuCiAgaWYoIWN1c3RvbWVyVG9r",
  "ZW4pewogICAgZXJyQm94LnRleHRDb250ZW50ID0gJ0LhuqFuIGPhuqduIMSRxINuZyBuaOG6rXAg",
  "dHLGsOG7m2Mga2hpIG7huqFwIHRp4buBbi4nOwogICAgZXJyQm94LmNsYXNzTGlzdC5hZGQoJ3No",
  "b3cnKTsKICAgIHJldHVybjsKICB9CiAgY29uc3QgYnRuID0gJCgnYnRuU3VibWl0VG9wdXBSZXF1",
  "ZXN0Jyk7CiAgY29uc3Qgb3JpZ2luYWxCdG5UZXh0ID0gYnRuLnRleHRDb250ZW50OwogIGJ0bi5k",
  "aXNhYmxlZCA9IHRydWU7CiAgYnRuLnRleHRDb250ZW50ID0gJ8SQYW5nIHThuqFvIG3DoyBRUi4u",
  "Lic7CiAgdHJ5ewogICAgY29uc3QgcmVzID0gYXdhaXQgZmV0Y2goQVBJX0JBU0UgKyAnL2FwaS90",
  "b3B1cC1yZXF1ZXN0JywgewogICAgICBtZXRob2Q6J1BPU1QnLCBoZWFkZXJzOnsnQ29udGVudC1U",
  "eXBlJzonYXBwbGljYXRpb24vanNvbid9LAogICAgICBib2R5OiBKU09OLnN0cmluZ2lmeSh7IHRv",
  "a2VuOiBjdXN0b21lclRva2VuLCBhbW91bnQsIG1ldGhvZDonYmFua190cmFuc2ZlcicgfSkKICAg",
  "IH0pOwoKICAgIC8vIMSQ4buNYyByZXNwb25zZSBk4bqhbmcgdGV4dCB0csaw4bubYywgcuG7k2kg",
  "beG7m2kgcGFyc2UgSlNPTiDigJQgxJHhu4Mga2jDtG5nICJudeG7kXQiIGzhu5dpIGtoaSBzZXJ2",
  "ZXIgdHLhuqMKICAgIC8vIHbhu4EgSFRNTC9s4buXaSA1MDIgKHbDrSBk4bulIFJlbmRlciDEkWFu",
  "ZyBraOG7n2kgxJHhu5luZyBs4bqhaSkgdGhheSB2w6wgSlNPTiBo4bujcCBs4buHLgogICAgY29u",
  "c3QgcmF3VGV4dCA9IGF3YWl0IHJlcy50ZXh0KCk7CiAgICBsZXQgZGF0YTsKICAgIHRyeXsKICAg",
  "ICAgZGF0YSA9IEpTT04ucGFyc2UocmF3VGV4dCk7CiAgICB9Y2F0Y2gocGFyc2VFcnIpewogICAg",
  "ICBjb25zb2xlLmVycm9yKCdbVG9wdXBdIFNlcnZlciBraMO0bmcgdHLhuqMgSlNPTiBo4bujcCBs",
  "4buHLiBTdGF0dXM6JywgcmVzLnN0YXR1cywgJ0JvZHk6JywgcmF3VGV4dC5zbGljZSgwLCAzMDAp",
  "KTsKICAgICAgdGhyb3cgbmV3IEVycm9yKCdNw6F5IGNo4bunIMSRYW5nIGto4bufaSDEkeG7mW5n",
  "IGzhuqFpIGhv4bq3YyBn4bq3cCBz4buxIGPhu5EgdOG6oW0gdGjhu51pLCB2dWkgbMOybmcgdGjh",
  "u60gbOG6oWkgc2F1IMOtdCBnacOieS4nKTsKICAgIH0KCiAgICBpZihyZXMuc3RhdHVzID09PSA0",
  "MDkgJiYgZGF0YS5yZXF1ZXN0KXsKICAgICAgLy8gxJDDoyBjw7MgMSB5w6p1IGPhuqd1IMSRYW5n",
  "IGNo4budIHjhu60gbMO9IOKAlCBoaeG7g24gdGjhu4sgbOG6oWkgxJHDum5nIFFSL8SR4bq/bSBu",
  "Z8aw4bujYyBj4bunYSB5w6p1IGPhuqd1IMSRw7MKICAgICAgLy8gdGhheSB2w6wgYsOhbyBs4buX",
  "aSBraMO0LCDEkeG7gyBraMOhY2gga2jDtG5nIGLhu4sga+G6uXQga2jDtG5nIGJp4bq/dCBsw6Bt",
  "IGfDrCB0aeG6v3AuCiAgICAgIG9wZW5Ub3B1cFFyU3RlcChkYXRhLnJlcXVlc3QpOwogICAgICBy",
  "ZXR1cm47CiAgICB9CiAgICBpZihyZXMuc3RhdHVzID09PSA0MDEpewogICAgICB0aHJvdyBuZXcg",
  "RXJyb3IoJ1BoacOqbiDEkcSDbmcgbmjhuq1wIMSRw6MgaOG6v3QgaOG6oW4sIHZ1aSBsw7JuZyDE",
  "kcSDbmcgbmjhuq1wIGzhuqFpIHLhu5NpIHRo4butIG7huqFwIHRp4buBbiBs4bqhaS4nKTsKICAg",
  "IH0KICAgIGlmKHJlcy5zdGF0dXMgPT09IDQyOSl7CiAgICAgIHRocm93IG5ldyBFcnJvcihkYXRh",
  "Lm1lc3NhZ2UgfHwgJ0LhuqFuIMSRYW5nIGfhu61pIHnDqnUgY+G6p3UgcXXDoSBuaGFuaCwgdnVp",
  "IGzDsm5nIHRo4butIGzhuqFpIHNhdSB2w6BpIHBow7p0LicpOwogICAgfQogICAgaWYoIXJlcy5v",
  "ayB8fCAhZGF0YS5vayl7CiAgICAgIC8vIExvZyBjaGkgdGnhur90IGzhu5dpIHRo4bqtdCByYSBj",
  "b25zb2xlIMSR4buDIGThu4UgY2jhuqluIMSRb8OhbiAodGhheSB2w6wgY2jhu4kgaGnhu4duIHRo",
  "w7RuZyBiw6FvIGNodW5nKS4KICAgICAgY29uc29sZS5lcnJvcignW1RvcHVwXSBH4butaSB5w6p1",
  "IGPhuqd1IG7huqFwIHRp4buBbiB0aOG6pXQgYuG6oWkuIFN0YXR1czonLCByZXMuc3RhdHVzLCAn",
  "UmVzcG9uc2U6JywgZGF0YSk7CiAgICAgIHRocm93IG5ldyBFcnJvcihkYXRhLm1lc3NhZ2UgfHwg",
  "KCdH4butaSB5w6p1IGPhuqd1IHRo4bqldCBi4bqhaSAobcOjIGzhu5dpOiAnICsgcmVzLnN0YXR1",
  "cyArICcpLCB2dWkgbMOybmcgdGjhu60gbOG6oWkuJykpOwogICAgfQogICAgb3BlblRvcHVwUXJT",
  "dGVwKGRhdGEucmVxdWVzdCk7CiAgfWNhdGNoKGUpewogICAgY29uc29sZS5lcnJvcignW1RvcHVw",
  "XSBM4buXaSBraGkgdOG6oW8gecOqdSBj4bqndSBu4bqhcCB0aeG7gW46JywgZSk7CiAgICBlcnJC",
  "b3gudGV4dENvbnRlbnQgPSBlLm1lc3NhZ2UgfHwgJ0PDsyBs4buXaSB44bqjeSByYSwgdnVpIGzD",
  "sm5nIHRo4butIGzhuqFpLiBO4bq/dSB24bqrbiBs4buXaSwgaMOjeSB04bqjaSBs4bqhaSB0cmFu",
  "Zy4nOwogICAgZXJyQm94LmNsYXNzTGlzdC5hZGQoJ3Nob3cnKTsKICB9ZmluYWxseXsKICAgIGJ0",
  "bi5kaXNhYmxlZCA9IGZhbHNlOwogICAgYnRuLnRleHRDb250ZW50ID0gb3JpZ2luYWxCdG5UZXh0",
  "OwogIH0KfSk7CgovKiBIaeG7g24gdGjhu4sgYsaw4bubYyBRUjogxJFp4buBbiDhuqNuaCBRUiDE",
  "keG7mW5nICjEkcOjIG5ow7puZyBz4buRIHRp4buBbiArIG7hu5lpIGR1bmcgQ0sgdOG7qyBzZXJ2",
  "ZXIpLCB0aMO0bmcgdGluCiAgIG5nw6JuIGjDoG5nLCB2w6Aga2jhu59pIMSR4buZbmcgxJHhu5Nu",
  "ZyBo4buTIMSR4bq/bSBuZ8aw4bujYyAzMCBwaMO6dCArIHBvbGxpbmcgdHLhuqFuZyB0aMOhaS4g",
  "Ki8KZnVuY3Rpb24gb3BlblRvcHVwUXJTdGVwKHJlcUVudHJ5KXsKICBjdXJyZW50VG9wdXBSZXF1",
  "ZXN0SWQgPSByZXFFbnRyeS5pZDsKICAkKCd0b3B1cFFySW1nJykuc3JjID0gcmVxRW50cnkucXJV",
  "cmwgfHwgJyc7CiAgJCgndG9wdXBRckFtb3VudCcpLnRleHRDb250ZW50ID0gZm10TW9uZXkocmVx",
  "RW50cnkuYW1vdW50KTsKICAkKCd0b3B1cFFyTm90ZScpLnRleHRDb250ZW50ID0gcmVxRW50cnku",
  "dHJhbnNmZXJOb3RlIHx8ICgnTkFQICcgKyBjdXN0b21lck5hbWUpOwogICQoJ3RvcHVwUXJBY2Nv",
  "dW50Tm8nKS50ZXh0Q29udGVudCA9ICcwMzY0ODM3MTE4JzsKICAkKCd0b3B1cFFyQWNjb3VudE5h",
  "bWUnKS50ZXh0Q29udGVudCA9ICdMVU9ORyBWQU4gVFVZRU4nOwogICQoJ3RvcHVwUXJFcnJvcicp",
  "LmNsYXNzTGlzdC5yZW1vdmUoJ3Nob3cnKTsKICBzaG93VG9wdXBTdGVwKCdxcicpOwogIHN0b3BU",
  "b3B1cFRpbWVycygpOwogIHN0YXJ0VG9wdXBDb3VudGRvd24ocmVxRW50cnkuZXhwaXJlc0F0KTsK",
  "ICBzdGFydFRvcHVwU3RhdHVzUG9sbGluZyhyZXFFbnRyeS5pZCk7Cn0KCmZ1bmN0aW9uIHJlbmRl",
  "ckhpc3RvcnlMaXN0KGNvbnRhaW5lciwgaXRlbXMsIGVtcHR5TXNnKXsKICBpZighaXRlbXMgfHwg",
  "IWl0ZW1zLmxlbmd0aCl7CiAgICBjb250YWluZXIuaW5uZXJIVE1MID0gYDxkaXYgY2xhc3M9Imhp",
  "c3RvcnktZW1wdHkiPiR7ZW1wdHlNc2d9PC9kaXY+YDsKICAgIHJldHVybjsKICB9CiAgY29udGFp",
  "bmVyLmlubmVySFRNTCA9IGl0ZW1zLm1hcChpdD0+ewogICAgaWYoaXQuc3RhdHVzICE9PSB1bmRl",
  "ZmluZWQpewogICAgICAvLyBt4bulYyBs4buLY2ggc+G7rSBu4bqhcCB0aeG7gW4KICAgICAgY29u",
  "c3Qgc3RhdHVzTGFiZWwgPSB7IHBlbmRpbmc6J8SQYW5nIGNo4budIGR1eeG7h3QnLCBhcHByb3Zl",
  "ZDonxJDDoyBkdXnhu4d0JywgcmVqZWN0ZWQ6J8SQw6MgdOG7qyBjaOG7kWknIH1baXQuc3RhdHVz",
  "XSB8fCBpdC5zdGF0dXM7CiAgICAgIHJldHVybiBgCiAgICAgICAgPGRpdiBjbGFzcz0iaGlzdG9y",
  "eS1pdGVtIj4KICAgICAgICAgIDxkaXY+CiAgICAgICAgICAgIDxkaXYgY2xhc3M9ImgtbWFpbiI+",
  "TuG6oXAgdGnhu4FuIMK3ICR7aXQubWV0aG9kPT09J2JhbmtfdHJhbnNmZXInID8gJ0NodXnhu4Nu",
  "IGtob+G6o24nIDogKGl0Lm1ldGhvZD09PSdhZG1pbl9tYW51YWwnID8gJ0FkbWluIGPhu5luZyB0",
  "YXknIDogaXQubWV0aG9kKX08L2Rpdj4KICAgICAgICAgICAgPGRpdiBjbGFzcz0iaC1zdWIiPiR7",
  "bmV3IERhdGUoaXQuY3JlYXRlZEF0KS50b0xvY2FsZVN0cmluZygndmktVk4nKX0gwrcgPHNwYW4g",
  "Y2xhc3M9InN0YXR1cy1waWxsICR7aXQuc3RhdHVzfSI+JHtzdGF0dXNMYWJlbH08L3NwYW4+PC9k",
  "aXY+CiAgICAgICAgICA8L2Rpdj4KICAgICAgICAgIDxkaXYgY2xhc3M9ImgtYW1vdW50IHBvcyI+",
  "KyR7Zm10TW9uZXkoaXQuYW1vdW50KX08L2Rpdj4KICAgICAgICA8L2Rpdj5gOwogICAgfQogICAg",
  "Ly8gbeG7pWMgbOG7i2NoIHPhu60gZ2lhbyBk4buLY2gKICAgIGNvbnN0IGlzUG9zaXRpdmUgPSBp",
  "dC5hbW91bnQgPj0gMDsKICAgIHJldHVybiBgCiAgICAgIDxkaXYgY2xhc3M9Imhpc3RvcnktaXRl",
  "bSI+CiAgICAgICAgPGRpdj4KICAgICAgICAgIDxkaXYgY2xhc3M9ImgtbWFpbiI+JHtpdC5ub3Rl",
  "IHx8IChpdC50eXBlPT09J3RvcHVwJyA/ICdO4bqhcCB0aeG7gW4nIDogJ0dpYW8gZOG7i2NoJyl9",
  "PC9kaXY+CiAgICAgICAgICA8ZGl2IGNsYXNzPSJoLXN1YiI+JHtuZXcgRGF0ZShpdC5jcmVhdGVk",
  "QXQpLnRvTG9jYWxlU3RyaW5nKCd2aS1WTicpfSDCtyBT4buRIGTGsCBzYXU6ICR7Zm10TW9uZXko",
  "aXQuYmFsYW5jZUFmdGVyKX08L2Rpdj4KICAgICAgICA8L2Rpdj4KICAgICAgICA8ZGl2IGNsYXNz",
  "PSJoLWFtb3VudCAke2lzUG9zaXRpdmUgPyAncG9zJyA6ICduZWcnfSI+JHtpc1Bvc2l0aXZlID8g",
  "JysnIDogJyd9JHtmbXRNb25leShpdC5hbW91bnQpfTwvZGl2PgogICAgICA8L2Rpdj5gOwogIH0p",
  "LmpvaW4oJycpOwp9Cgphc3luYyBmdW5jdGlvbiBsb2FkQ3VzdG9tZXJIaXN0b3J5KCl7CiAgdHJ5",
  "ewogICAgY29uc3QgcmVzID0gYXdhaXQgZmV0Y2goQVBJX0JBU0UgKyAnL2FwaS9hdXRoL2hpc3Rv",
  "cnknLCB7IGhlYWRlcnM6eyAnQXV0aG9yaXphdGlvbic6ICdCZWFyZXIgJyArIGN1c3RvbWVyVG9r",
  "ZW4gfSB9KTsKICAgIGlmKCFyZXMub2spIHRocm93IG5ldyBFcnJvcignbm90X2xvZ2dlZF9pbicp",
  "OwogICAgcmV0dXJuIGF3YWl0IHJlcy5qc29uKCk7CiAgfWNhdGNoKGUpewogICAgcmV0dXJuIHsg",
  "b2s6ZmFsc2UsIHRvcHVwSGlzdG9yeTpbXSwgdHJhbnNhY3Rpb25IaXN0b3J5OltdIH07CiAgfQp9",
  "CgokKCdkZFRvcHVwSGlzdG9yeScpLmFkZEV2ZW50TGlzdGVuZXIoJ2NsaWNrJywgYXN5bmMgKCk9",
  "PnsKICBjbG9zZURyb3Bkb3duKCk7CiAgJCgndG9wdXBIaXN0b3J5TW9kYWxCZycpLmNsYXNzTGlz",
  "dC5hZGQoJ3Nob3cnKTsKICAkKCd0b3B1cEhpc3RvcnlMaXN0JykuaW5uZXJIVE1MID0gJzxkaXYg",
  "Y2xhc3M9Imhpc3RvcnktZW1wdHkiPsSQYW5nIHThuqNpLi4uPC9kaXY+JzsKICBjb25zdCBkYXRh",
  "ID0gYXdhaXQgbG9hZEN1c3RvbWVySGlzdG9yeSgpOwogIHJlbmRlckhpc3RvcnlMaXN0KCQoJ3Rv",
  "cHVwSGlzdG9yeUxpc3QnKSwgZGF0YS50b3B1cEhpc3RvcnksICdDaMawYSBjw7MgbMaw4bujdCBu",
  "4bqhcCB0aeG7gW4gbsOgbycpOwp9KTsKJCgnYnRuQ2xvc2VUb3B1cEhpc3RvcnknKS5hZGRFdmVu",
  "dExpc3RlbmVyKCdjbGljaycsICgpPT4gJCgndG9wdXBIaXN0b3J5TW9kYWxCZycpLmNsYXNzTGlz",
  "dC5yZW1vdmUoJ3Nob3cnKSk7CgokKCdkZFR4SGlzdG9yeScpLmFkZEV2ZW50TGlzdGVuZXIoJ2Ns",
  "aWNrJywgYXN5bmMgKCk9PnsKICBjbG9zZURyb3Bkb3duKCk7CiAgJCgndHhIaXN0b3J5TW9kYWxC",
  "ZycpLmNsYXNzTGlzdC5hZGQoJ3Nob3cnKTsKICAkKCd0eEhpc3RvcnlMaXN0JykuaW5uZXJIVE1M",
  "ID0gJzxkaXYgY2xhc3M9Imhpc3RvcnktZW1wdHkiPsSQYW5nIHThuqNpLi4uPC9kaXY+JzsKICBj",
  "b25zdCBkYXRhID0gYXdhaXQgbG9hZEN1c3RvbWVySGlzdG9yeSgpOwogIHJlbmRlckhpc3RvcnlM",
  "aXN0KCQoJ3R4SGlzdG9yeUxpc3QnKSwgZGF0YS50cmFuc2FjdGlvbkhpc3RvcnksICdDaMawYSBj",
  "w7MgZ2lhbyBk4buLY2ggbsOgbycpOwp9KTsKJCgnYnRuQ2xvc2VUeEhpc3RvcnknKS5hZGRFdmVu",
  "dExpc3RlbmVyKCdjbGljaycsICgpPT4gJCgndHhIaXN0b3J5TW9kYWxCZycpLmNsYXNzTGlzdC5y",
  "ZW1vdmUoJ3Nob3cnKSk7CgovKiAtLS0tLS0tLS0tIE1vZGFsIFF14bqjbiBsw70ga2V5IChrZXkg",
  "xJHDoyBtdWEpIC0tLS0tLS0tLS0gKi8KY29uc3QgTVlfS0VZX1NUQVRVU19MQUJFTCA9IHsgYXZh",
  "aWxhYmxlOidDw7JuIGjDoG5nJywgc29sZDonxJDDoyBiw6FuJywgYmFubmVkOidC4buLIGPhuqVt",
  "JywgZXhwaXJlZDonSOG6v3QgaOG6oW4nLCB1bmFjdGl2YXRlZDonQ2jGsGEga8OtY2ggaG/huqF0",
  "JyB9OwoKZnVuY3Rpb24gZm10S2V5VW5pdExhYmVsKHVuaXQpewogIHJldHVybiB1bml0PT09J2hv",
  "dXInID8gJ2dp4budJyA6IHVuaXQ9PT0nbW9udGgnID8gJ3Row6FuZycgOiAnbmfDoHknOwp9Cgpm",
  "dW5jdGlvbiByZW5kZXJNeUtleXNMaXN0KGl0ZW1zKXsKICBjb25zdCBjb250YWluZXIgPSAkKCdt",
  "eUtleXNMaXN0Jyk7CiAgaWYoIWl0ZW1zIHx8ICFpdGVtcy5sZW5ndGgpewogICAgY29udGFpbmVy",
  "LmlubmVySFRNTCA9ICc8ZGl2IGNsYXNzPSJoaXN0b3J5LWVtcHR5Ij5C4bqhbiBjaMawYSBtdWEg",
  "a2V5IG7DoG88L2Rpdj4nOwogICAgcmV0dXJuOwogIH0KICBjb250YWluZXIuaW5uZXJIVE1MID0g",
  "aXRlbXMubWFwKGs9PnsKICAgIGNvbnN0IHN0YXR1c0xhYmVsID0gTVlfS0VZX1NUQVRVU19MQUJF",
  "TFtrLnN0YXR1c10gfHwgay5zdGF0dXM7CiAgICBsZXQgZXhwaXJ5TGluZTsKICAgIGlmKGsuaGFz",
  "RXhwaXJ5UGxhbiAmJiAhay5hY3RpdmF0ZWQpewogICAgICBleHBpcnlMaW5lID0gYEjhuqFuIGTD",
  "uW5nOiA8Yj5DaMawYSBrw61jaCBob+G6oXQ8L2I+IOKAlCBz4bq9IGTDuW5nIMSRxrDhu6NjICR7",
  "ay5leHBpcnlBbW91bnR8fCc/J30gJHtmbXRLZXlVbml0TGFiZWwoay5leHBpcnlVbml0KX0ga+G7",
  "gyB04burIGzhuqduIMSR4bqndSBz4butIGThu6VuZ2A7CiAgICB9IGVsc2UgaWYoay5leHBpcmVz",
  "QXQpewogICAgICBleHBpcnlMaW5lID0gYEjhuqFuIGTDuW5nOiA8Yj4ke25ldyBEYXRlKGsuZXhw",
  "aXJlc0F0KS50b0xvY2FsZVN0cmluZygndmktVk4nKX08L2I+YDsKICAgIH0gZWxzZSB7CiAgICAg",
  "IGV4cGlyeUxpbmUgPSAnSOG6oW4gZMO5bmc6IDxiPktow7RuZyBnaeG7m2kgaOG6oW48L2I+JzsK",
  "ICAgIH0KICAgIGNvbnN0IHNvbGRMaW5lID0gay5zb2xkQXQgPyBuZXcgRGF0ZShrLnNvbGRBdCku",
  "dG9Mb2NhbGVTdHJpbmcoJ3ZpLVZOJykgOiAn4oCUJzsKICAgIHJldHVybiBgCiAgICAgIDxkaXYg",
  "Y2xhc3M9ImtleS1pdGVtIj4KICAgICAgICA8ZGl2IGNsYXNzPSJrLXRvcCI+CiAgICAgICAgICA8",
  "c3BhbiBjbGFzcz0iay12YWx1ZSI+JHtrLnZhbHVlfTwvc3Bhbj4KICAgICAgICAgIDxidXR0b24g",
  "Y2xhc3M9ImstY29weSIgZGF0YS1rZXk9IiR7ay52YWx1ZX0iPlNhbyBjaMOpcDwvYnV0dG9uPgog",
  "ICAgICAgIDwvZGl2PgogICAgICAgIDxkaXYgY2xhc3M9ImstbWV0YSI+CiAgICAgICAgICA8c3Bh",
  "biBjbGFzcz0ic3RhdHVzLXBpbGwgJHtrLnN0YXR1c30iPiR7c3RhdHVzTGFiZWx9PC9zcGFuPiDC",
  "twogICAgICAgICAgJHtrLnR5cGU9PT0ncHJlbWl1bScgPyAn4piFIFByZW1pdW0nIDogJ1RoxrDh",
  "u51uZyd9IMK3CiAgICAgICAgICBUaGnhur90IGLhu4s6ICR7ay5kZXZpY2VzVXNlZHx8MH0vJHtr",
  "Lm1heERldmljZXN8fDF9PGJyPgogICAgICAgICAgJHtleHBpcnlMaW5lfTxicj4KICAgICAgICAg",
  "IE5nw6B5IG11YTogJHtzb2xkTGluZX0KICAgICAgICA8L2Rpdj4KICAgICAgPC9kaXY+YDsKICB9",
  "KS5qb2luKCcnKTsKfQoKYXN5bmMgZnVuY3Rpb24gbG9hZE15S2V5cygpewogIHRyeXsKICAgIGNv",
  "bnN0IHJlcyA9IGF3YWl0IGZldGNoKEFQSV9CQVNFICsgJy9hcGkvY3VzdG9tZXIva2V5cycsIHsg",
  "aGVhZGVyczp7ICdBdXRob3JpemF0aW9uJzogJ0JlYXJlciAnICsgY3VzdG9tZXJUb2tlbiB9IH0p",
  "OwogICAgaWYoIXJlcy5vaykgdGhyb3cgbmV3IEVycm9yKCdub3RfbG9nZ2VkX2luJyk7CiAgICBj",
  "b25zdCBkYXRhID0gYXdhaXQgcmVzLmpzb24oKTsKICAgIHJldHVybiAoZGF0YS5vayAmJiBkYXRh",
  "LmtleXMpID8gZGF0YS5rZXlzIDogW107CiAgfWNhdGNoKGUpewogICAgcmV0dXJuIFtdOwogIH0K",
  "fQoKJCgnZGRNeUtleXMnKS5hZGRFdmVudExpc3RlbmVyKCdjbGljaycsIGFzeW5jICgpPT57CiAg",
  "Y2xvc2VEcm9wZG93bigpOwogIGlmKCFjdXN0b21lclRva2VuKXsgb3BlbkF1dGhNb2RhbCgpOyBy",
  "ZXR1cm47IH0KICAkKCdteUtleXNNb2RhbEJnJykuY2xhc3NMaXN0LmFkZCgnc2hvdycpOwogICQo",
  "J215S2V5c0xpc3QnKS5pbm5lckhUTUwgPSAnPGRpdiBjbGFzcz0iaGlzdG9yeS1lbXB0eSI+xJBh",
  "bmcgdOG6o2kuLi48L2Rpdj4nOwogIGNvbnN0IGtleXNMaXN0ID0gYXdhaXQgbG9hZE15S2V5cygp",
  "OwogIHJlbmRlck15S2V5c0xpc3Qoa2V5c0xpc3QpOwp9KTsKJCgnYnRuQ2xvc2VNeUtleXMnKS5h",
  "ZGRFdmVudExpc3RlbmVyKCdjbGljaycsICgpPT4gJCgnbXlLZXlzTW9kYWxCZycpLmNsYXNzTGlz",
  "dC5yZW1vdmUoJ3Nob3cnKSk7CiQoJ215S2V5c0xpc3QnKS5hZGRFdmVudExpc3RlbmVyKCdjbGlj",
  "aycsIChlKT0+ewogIGNvbnN0IGJ0biA9IGUudGFyZ2V0LmNsb3Nlc3QoJy5rLWNvcHknKTsKICBp",
  "ZighYnRuKSByZXR1cm47CiAgbmF2aWdhdG9yLmNsaXBib2FyZC53cml0ZVRleHQoYnRuLmRhdGFz",
  "ZXQua2V5KS50aGVuKCgpPT4gc2hvd1RvYXN0KCfEkMOjIHNhbyBjaMOpcCBrZXknKSkuY2F0Y2go",
  "KCk9PiBzaG93VG9hc3QoJ0tow7RuZyBzYW8gY2jDqXAgxJHGsOG7o2MsIHZ1aSBsw7JuZyBjb3B5",
  "IHRo4bunIGPDtG5nJykpOwp9KTsKCi8qIC0tLS0tLS0tLS0gTW9kYWwgxJDEg25nIG5o4bqtcCAv",
  "IMSQxINuZyBrw70gLS0tLS0tLS0tLSAqLwpsZXQgcGVuZGluZ0J1eVByb2R1Y3RJZCA9IG51bGw7",
  "IC8vIHPhuqNuIHBo4bqpbSBraMOhY2ggYuG6pW0gIk11YSIgdHLGsOG7m2Mga2hpIMSRxINuZyBu",
  "aOG6rXAgeG9uZwoKZnVuY3Rpb24gb3BlbkF1dGhNb2RhbCgpewogICQoJ2F1dGhFcnJvcicpLmNs",
  "YXNzTGlzdC5yZW1vdmUoJ3Nob3cnKTsKICAkKCdhdXRoTW9kYWxCZycpLmNsYXNzTGlzdC5hZGQo",
  "J3Nob3cnKTsKfQpmdW5jdGlvbiBjbG9zZUF1dGhNb2RhbCgpeyAkKCdhdXRoTW9kYWxCZycpLmNs",
  "YXNzTGlzdC5yZW1vdmUoJ3Nob3cnKTsgfQoKJCgnYnRuT3BlbkF1dGgnKS5hZGRFdmVudExpc3Rl",
  "bmVyKCdjbGljaycsICgpPT4gb3BlbkF1dGhNb2RhbCgpKTsKJCgnYnRuQ2xvc2VBdXRoJykuYWRk",
  "RXZlbnRMaXN0ZW5lcignY2xpY2snLCBjbG9zZUF1dGhNb2RhbCk7CgokKCd0YWJMb2dpbicpLmFk",
  "ZEV2ZW50TGlzdGVuZXIoJ2NsaWNrJywgKCk9PnsKICAkKCd0YWJMb2dpbicpLmNsYXNzTGlzdC5h",
  "ZGQoJ2FjdGl2ZScpOyAkKCd0YWJSZWdpc3RlcicpLmNsYXNzTGlzdC5yZW1vdmUoJ2FjdGl2ZScp",
  "OwogICQoJ2F1dGhGb3JtTG9naW4nKS5zdHlsZS5kaXNwbGF5ID0gJyc7ICQoJ2F1dGhGb3JtUmVn",
  "aXN0ZXInKS5zdHlsZS5kaXNwbGF5ID0gJ25vbmUnOwogICQoJ2J0blN1Ym1pdEF1dGgnKS50ZXh0",
  "Q29udGVudCA9ICfEkMSDbmcgbmjhuq1wJzsKICAkKCdhdXRoRXJyb3InKS5jbGFzc0xpc3QucmVt",
  "b3ZlKCdzaG93Jyk7Cn0pOwokKCd0YWJSZWdpc3RlcicpLmFkZEV2ZW50TGlzdGVuZXIoJ2NsaWNr",
  "JywgKCk9PnsKICAkKCd0YWJSZWdpc3RlcicpLmNsYXNzTGlzdC5hZGQoJ2FjdGl2ZScpOyAkKCd0",
  "YWJMb2dpbicpLmNsYXNzTGlzdC5yZW1vdmUoJ2FjdGl2ZScpOwogICQoJ2F1dGhGb3JtUmVnaXN0",
  "ZXInKS5zdHlsZS5kaXNwbGF5ID0gJyc7ICQoJ2F1dGhGb3JtTG9naW4nKS5zdHlsZS5kaXNwbGF5",
  "ID0gJ25vbmUnOwogICQoJ2J0blN1Ym1pdEF1dGgnKS50ZXh0Q29udGVudCA9ICfEkMSDbmcga8O9",
  "JzsKICAkKCdhdXRoRXJyb3InKS5jbGFzc0xpc3QucmVtb3ZlKCdzaG93Jyk7Cn0pOwoKJCgnYnRu",
  "U3VibWl0QXV0aCcpLmFkZEV2ZW50TGlzdGVuZXIoJ2NsaWNrJywgYXN5bmMgKCk9PnsKICBjb25z",
  "dCBpc1JlZ2lzdGVyID0gJCgndGFiUmVnaXN0ZXInKS5jbGFzc0xpc3QuY29udGFpbnMoJ2FjdGl2",
  "ZScpOwogIGNvbnN0IGVyckJveCA9ICQoJ2F1dGhFcnJvcicpOwogIGVyckJveC5jbGFzc0xpc3Qu",
  "cmVtb3ZlKCdzaG93Jyk7CgogIHRyeXsKICAgIGlmKGlzUmVnaXN0ZXIpewogICAgICBjb25zdCB1",
  "c2VybmFtZSA9ICQoJ3JlZ1VzZXJuYW1lJykudmFsdWUudHJpbSgpOwogICAgICBjb25zdCBwYXNz",
  "d29yZCA9ICQoJ3JlZ1Bhc3N3b3JkJykudmFsdWU7CiAgICAgIGNvbnN0IGNvbmZpcm1QYXNzID0g",
  "JCgncmVnUGFzc3dvcmRDb25maXJtJykudmFsdWU7CiAgICAgIGlmKCF1c2VybmFtZSB8fCAhcGFz",
  "c3dvcmQpeyB0aHJvdyBuZXcgRXJyb3IoJ1Z1aSBsw7JuZyBuaOG6rXAgxJHhuqd5IMSR4bunIHTD",
  "qm4gxJHEg25nIG5o4bqtcCB2w6AgbeG6rXQga2jhuql1Jyk7IH0KICAgICAgaWYocGFzc3dvcmQu",
  "bGVuZ3RoIDwgOCl7IHRocm93IG5ldyBFcnJvcignTeG6rXQga2jhuql1IGPhuqduIHThu5FpIHRo",
  "aeG7g3UgOCBrw70gdOG7sScpOyB9CiAgICAgIGlmKHBhc3N3b3JkICE9PSBjb25maXJtUGFzcyl7",
  "IHRocm93IG5ldyBFcnJvcignTeG6rXQga2jhuql1IG5o4bqtcCBs4bqhaSBraMO0bmcga2jhu5tw",
  "Jyk7IH0KCiAgICAgIGNvbnN0IHJlcyA9IGF3YWl0IGZldGNoKEFQSV9CQVNFICsgJy9hcGkvYXV0",
  "aC9yZWdpc3RlcicsIHsKICAgICAgICBtZXRob2Q6J1BPU1QnLCBoZWFkZXJzOnsnQ29udGVudC1U",
  "eXBlJzonYXBwbGljYXRpb24vanNvbid9LAogICAgICAgIGJvZHk6IEpTT04uc3RyaW5naWZ5KHsg",
  "dXNlcm5hbWUsIHBhc3N3b3JkIH0pCiAgICAgIH0pOwogICAgICBjb25zdCBkYXRhID0gYXdhaXQg",
  "cmVzLmpzb24oKTsKICAgICAgaWYoIXJlcy5vayB8fCAhZGF0YS5vayl7CiAgICAgICAgaWYoZGF0",
  "YS5lcnJvciA9PT0gJ3VzZXJuYW1lX3Rha2VuJykgdGhyb3cgbmV3IEVycm9yKCdUw6puIMSRxINu",
  "ZyBuaOG6rXAgxJHDoyB04buTbiB04bqhaSwgdnVpIGzDsm5nIGNo4buNbiB0w6puIGtow6FjJyk7",
  "CiAgICAgICAgaWYoZGF0YS5lcnJvciA9PT0gJ3Bhc3N3b3JkX3Rvb19zaG9ydCcpIHRocm93IG5l",
  "dyBFcnJvcihkYXRhLm1lc3NhZ2UgfHwgJ03huq10IGto4bqpdSBwaOG6o2kgY8OzIHThu5FpIHRo",
  "aeG7g3UgOCBrw70gdOG7sScpOwogICAgICAgIHRocm93IG5ldyBFcnJvcignxJDEg25nIGvDvSB0",
  "aOG6pXQgYuG6oWksIHZ1aSBsw7JuZyB0aOG7rSBs4bqhaScpOwogICAgICB9CiAgICAgIGN1c3Rv",
  "bWVyVG9rZW4gPSBkYXRhLnRva2VuOyBjdXN0b21lck5hbWUgPSBkYXRhLnVzZXJuYW1lOyBjdXN0",
  "b21lclJvbGUgPSBkYXRhLnJvbGUgfHwgJ2N1c3RvbWVyJzsgY3VzdG9tZXJCYWxhbmNlID0gMDsK",
  "ICAgIH0gZWxzZSB7CiAgICAgIGNvbnN0IHVzZXJuYW1lID0gJCgnbG9naW5Vc2VybmFtZScpLnZh",
  "bHVlLnRyaW0oKTsKICAgICAgY29uc3QgcGFzc3dvcmQgPSAkKCdsb2dpblBhc3N3b3JkJykudmFs",
  "dWU7CiAgICAgIGlmKCF1c2VybmFtZSB8fCAhcGFzc3dvcmQpeyB0aHJvdyBuZXcgRXJyb3IoJ1Z1",
  "aSBsw7JuZyBuaOG6rXAgdMOqbiDEkcSDbmcgbmjhuq1wIHbDoCBt4bqtdCBraOG6qXUnKTsgfQoK",
  "ICAgICAgY29uc3QgcmVzID0gYXdhaXQgZmV0Y2goQVBJX0JBU0UgKyAnL2FwaS9hdXRoL2xvZ2lu",
  "JywgewogICAgICAgIG1ldGhvZDonUE9TVCcsIGhlYWRlcnM6eydDb250ZW50LVR5cGUnOidhcHBs",
  "aWNhdGlvbi9qc29uJ30sCiAgICAgICAgYm9keTogSlNPTi5zdHJpbmdpZnkoeyB1c2VybmFtZSwg",
  "cGFzc3dvcmQgfSkKICAgICAgfSk7CiAgICAgIGNvbnN0IGRhdGEgPSBhd2FpdCByZXMuanNvbigp",
  "OwogICAgICBpZighcmVzLm9rIHx8ICFkYXRhLm9rKXsKICAgICAgICBjb25zdCBtYXAgPSB7CiAg",
  "ICAgICAgICBzZWxsZXJfYmFubmVkOiAnVMOgaSBraG/huqNuIG5nxrDhu51pIGLDoW4gxJHDoyBi",
  "4buLIGPhuqVtJywKICAgICAgICAgIHNlbGxlcl9leHBpcmVkOiAnVMOgaSBraG/huqNuIG5nxrDh",
  "u51pIGLDoW4gxJHDoyBo4bq/dCBo4bqhbiBz4butIGThu6VuZycKICAgICAgICB9OwogICAgICAg",
  "IHRocm93IG5ldyBFcnJvcihtYXBbZGF0YS5lcnJvcl0gfHwgJ1NhaSB0w6puIMSRxINuZyBuaOG6",
  "rXAgaG/hurdjIG3huq10IGto4bqpdScpOwogICAgICB9CiAgICAgIGN1c3RvbWVyVG9rZW4gPSBk",
  "YXRhLnRva2VuOyBjdXN0b21lck5hbWUgPSBkYXRhLnVzZXJuYW1lOyBjdXN0b21lclJvbGUgPSBk",
  "YXRhLnJvbGUgfHwgJ2N1c3RvbWVyJzsgY3VzdG9tZXJCYWxhbmNlID0gZGF0YS5iYWxhbmNlIHx8",
  "IDA7CgogICAgICAvKiAtLS0tIEfhu5lwIMSRxINuZyBuaOG6rXA6IG7hur91IHTDoGkga2hv4bqj",
  "biB24burYSDEkcSDbmcgbmjhuq1wIGzDoCBBRE1JTiBob+G6t2MgTkfGr+G7nEkgQsOBTiAoc2Vs",
  "bGVyKSwKICAgICAgICAgdOG7sSDEkeG7mW5nIGNodXnhu4NuIHRo4bqzbmcgdsOgbyB0cmFuZyBx",
  "deG6o24gdHLhu4sgKC9hZG1pbikg4oCUIGtow7RuZyBj4bqnbiBiaeG6v3QvZ8O1IGxpbmsgcmnD",
  "qm5nLgogICAgICAgICBEw7luZyDEkcO6bmcgY8ahIGNo4bq/ICJnaGkgbmjhu5sgxJHEg25nIG5o",
  "4bqtcCIgxJHDoyBjw7Mgc+G6tW4gdHJvbmcgL2FkbWluIChsb2NhbFN0b3JhZ2Uga2V5CiAgICAg",
  "ICAgICdrZXl2YXVsdF9yZW1lbWJlcicpIMSR4buDIC9hZG1pbiB04buxIMSRaeG7gW4gc+G6tW4g",
  "KyB04buxIMSRxINuZyBuaOG6rXAsIGtow7RuZyBj4bqnbiBnw7UgbOG6oWkuIC0tLS0gKi8KICAg",
  "ICAgaWYoZGF0YS5yb2xlID09PSAnYWRtaW4nIHx8IGRhdGEucm9sZSA9PT0gJ3NlbGxlcicpewog",
  "ICAgICAgIHRyeXsKICAgICAgICAgIGxvY2FsU3RvcmFnZS5zZXRJdGVtKCdrZXl2YXVsdF9yZW1l",
  "bWJlcicsIEpTT04uc3RyaW5naWZ5KHsgdXNlcjogdXNlcm5hbWUsIHBhc3M6IHBhc3N3b3JkLCBh",
  "dXRvTG9naW46IHRydWUgfSkpOwogICAgICAgIH1jYXRjaChlKXsgLyogdHLDrG5oIGR1eeG7h3Qg",
  "Y2jhurduIGxvY2FsU3RvcmFnZSB0aMOsIHRow7RpLCBhZG1pbi9zZWxsZXIgdOG7sSB2w6BvIC9h",
  "ZG1pbiB2w6AgZ8O1IGzhuqFpICovIH0KICAgICAgICBzaG93VG9hc3QoYFhpbiBjaMOgbyAke2Rh",
  "dGEudXNlcm5hbWV9ISDEkGFuZyBjaHV54buDbiB2w6BvIHRyYW5nIHF14bqjbiB0cuG7iy4uLmAp",
  "OwogICAgICAgIHdpbmRvdy5sb2NhdGlvbi5ocmVmID0gJy9hZG1pbic7CiAgICAgICAgcmV0dXJu",
  "OwogICAgICB9CiAgICB9CgogICAgbG9jYWxTdG9yYWdlLnNldEl0ZW0oJ2t2X3N0b3JlX3Rva2Vu",
  "JywgY3VzdG9tZXJUb2tlbik7CiAgICBsb2NhbFN0b3JhZ2Uuc2V0SXRlbSgna3Zfc3RvcmVfdXNl",
  "cm5hbWUnLCBjdXN0b21lck5hbWUpOwogICAgdXBkYXRlQWNjb3VudFVJKCk7CiAgICBjbG9zZUF1",
  "dGhNb2RhbCgpOwogICAgc2hvd1RvYXN0KCdYaW4gY2jDoG8sICcgKyBjdXN0b21lck5hbWUgKyAn",
  "IScpOwoKICAgIGlmKHBlbmRpbmdCdXlQcm9kdWN0SWQpewogICAgICBjb25zdCBwaWQgPSBwZW5k",
  "aW5nQnV5UHJvZHVjdElkOwogICAgICBwZW5kaW5nQnV5UHJvZHVjdElkID0gbnVsbDsKICAgICAg",
  "b3BlbkNoZWNrb3V0TW9kYWwocGlkKTsKICAgIH0KICB9Y2F0Y2goZSl7CiAgICBlcnJCb3gudGV4",
  "dENvbnRlbnQgPSBlLm1lc3NhZ2UgfHwgJ0PDsyBs4buXaSB44bqjeSByYSwgdnVpIGzDsm5nIHRo",
  "4butIGzhuqFpJzsKICAgIGVyckJveC5jbGFzc0xpc3QuYWRkKCdzaG93Jyk7CiAgfQp9KTsKCi8q",
  "IC0tLS0tLS0tLS0gRGFuaCBzw6FjaCBz4bqjbiBwaOG6qW0gLS0tLS0tLS0tLSAqLwpsZXQgcHJv",
  "ZHVjdHMgPSBbXTsKCmFzeW5jIGZ1bmN0aW9uIGxvYWRQcm9kdWN0cygpewogIHRyeXsKICAgIGNv",
  "bnN0IHJlcyA9IGF3YWl0IGZldGNoKEFQSV9CQVNFICsgJy9hcGkvcHJvZHVjdHMnLCB7IGNhY2hl",
  "Oiduby1zdG9yZScgfSk7CiAgICBwcm9kdWN0cyA9IGF3YWl0IHJlcy5qc29uKCk7CiAgfWNhdGNo",
  "KGUpewogICAgY29uc29sZS53YXJuKCdbS2V5VmF1bHQgU3RvcmVdIEtow7RuZyB04bqjaSDEkcaw",
  "4bujYyBkYW5oIHPDoWNoIHPhuqNuIHBo4bqpbScsIGUpOwogICAgcHJvZHVjdHMgPSBbXTsKICB9",
  "CiAgcmVuZGVyUHJvZHVjdHMoKTsKfQoKZnVuY3Rpb24gZm10RHVyYXRpb24ocCl7CiAgaWYocC5k",
  "dXJhdGlvblVuaXQ9PT0ndW5saW1pdGVkJyB8fCAhcC5kdXJhdGlvbkFtb3VudCkgcmV0dXJuICdL",
  "aMO0bmcgZ2nhu5tpIGjhuqFuJzsKICBjb25zdCB1bml0TGFiZWwgPSBwLmR1cmF0aW9uVW5pdD09",
  "PSdob3VyJyA/ICdnaeG7nScgOiBwLmR1cmF0aW9uVW5pdD09PSdtb250aCcgPyAndGjDoW5nJyA6",
  "ICduZ8OgeSc7CiAgcmV0dXJuIHAuZHVyYXRpb25BbW91bnQgKyAnICcgKyB1bml0TGFiZWw7Cn0K",
  "CmZ1bmN0aW9uIHJlbmRlclByb2R1Y3RzKCl7CiAgY29uc3QgZ3JpZCA9ICQoJ3Byb2R1Y3RHcmlk",
  "Jyk7CiAgY29uc3QgZW1wdHkgPSAkKCdlbXB0eVN0YXRlJyk7CiAgZ3JpZC5pbm5lckhUTUwgPSAn",
  "JzsKICBlbXB0eS5zdHlsZS5kaXNwbGF5ID0gcHJvZHVjdHMubGVuZ3RoID8gJ25vbmUnIDogJ2Js",
  "b2NrJzsKCiAgcHJvZHVjdHMuZm9yRWFjaChwPT57CiAgICBjb25zdCBpblN0b2NrID0gKHAuc3Rv",
  "Y2t8fDApID4gMDsKICAgIGNvbnN0IGNhcmQgPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCdkaXYn",
  "KTsKICAgIGNhcmQuY2xhc3NOYW1lID0gJ2NhcmQnOwogICAgY2FyZC5pbm5lckhUTUwgPSBgCiAg",
  "ICAgIDxkaXYgY2xhc3M9ImxvZ28iPiR7cC5sb2dvID8gYDxpbWcgc3JjPSIke3AubG9nb30iPmAg",
  "OiAn8J+Tpid9PC9kaXY+CiAgICAgIDxoMz4ke3AubmFtZX08L2gzPgogICAgICA8ZGl2IGNsYXNz",
  "PSJwcmljZSI+JHtmbXRNb25leShwLnByaWNlKX08L2Rpdj4KICAgICAgPGRpdiBjbGFzcz0ibWV0",
  "YSI+CiAgICAgICAgPHNwYW4+4o+xIFRo4budaSBo4bqhbjogPGI+JHtmbXREdXJhdGlvbihwKX08",
  "L2I+PC9zcGFuPgogICAgICAgIDxzcGFuPvCfk7EgVGhp4bq/dCBi4buLOiA8Yj4ke3AubWF4RGV2",
  "aWNlc3x8MX08L2I+PC9zcGFuPgogICAgICAgIDxzcGFuIGNsYXNzPSJzdG9jayAke2luU3RvY2sg",
  "PyAnaW4nIDogJ291dCd9Ij4ke2luU3RvY2sgPyAn4pyUIEPDsm4gJytwLnN0b2NrKycga2V5JyA6",
  "ICfinJYgSOG6v3QgaMOgbmcnfTwvc3Bhbj4KICAgICAgPC9kaXY+CiAgICAgIDxidXR0b24gY2xh",
  "c3M9ImJ0biBidXktYnRuIiBkYXRhLWlkPSIke3AuaWR9IiAke2luU3RvY2sgPyAnJyA6ICdkaXNh",
  "YmxlZCd9PiR7aW5TdG9jayA/ICdNdWEgbmdheScgOiAnSOG6v3QgaMOgbmcnfTwvYnV0dG9uPgog",
  "ICAgYDsKICAgIGdyaWQuYXBwZW5kQ2hpbGQoY2FyZCk7CiAgfSk7Cn0KCmRvY3VtZW50LmdldEVs",
  "ZW1lbnRCeUlkKCdwcm9kdWN0R3JpZCcpLmFkZEV2ZW50TGlzdGVuZXIoJ2NsaWNrJywgKGUpPT57",
  "CiAgY29uc3QgYnRuID0gZS50YXJnZXQuY2xvc2VzdCgnLmJ1eS1idG4nKTsKICBpZighYnRuIHx8",
  "IGJ0bi5kaXNhYmxlZCkgcmV0dXJuOwogIGNvbnN0IGlkID0gYnRuLmRhdGFzZXQuaWQ7CiAgaWYo",
  "IWN1c3RvbWVyVG9rZW4pewogICAgcGVuZGluZ0J1eVByb2R1Y3RJZCA9IGlkOwogICAgb3BlbkF1",
  "dGhNb2RhbCgpOwogICAgcmV0dXJuOwogIH0KICBvcGVuQ2hlY2tvdXRNb2RhbChpZCk7Cn0pOwoK",
  "LyogLS0tLS0tLS0tLSBNb2RhbCBUaGFuaCB0b8OhbiAtLS0tLS0tLS0tICovCmxldCBjaGVja291",
  "dFByb2R1Y3QgPSBudWxsOwpsZXQgYXBwbGllZERpc2NvdW50UGVyY2VudCA9IDA7CgpmdW5jdGlv",
  "biBvcGVuQ2hlY2tvdXRNb2RhbChwcm9kdWN0SWQpewogIGNoZWNrb3V0UHJvZHVjdCA9IHByb2R1",
  "Y3RzLmZpbmQocD0+cC5pZD09PXByb2R1Y3RJZCk7CiAgaWYoIWNoZWNrb3V0UHJvZHVjdCl7IHNo",
  "b3dUb2FzdCgnU+G6o24gcGjhuqltIGtow7RuZyBjw7JuIHThu5NuIHThuqFpLCB2dWkgbMOybmcg",
  "dOG6o2kgbOG6oWkgdHJhbmcnKTsgcmV0dXJuOyB9CiAgYXBwbGllZERpc2NvdW50UGVyY2VudCA9",
  "IDA7CiAgJCgnY2hlY2tvdXRQcm9kdWN0TmFtZScpLnRleHRDb250ZW50ID0gY2hlY2tvdXRQcm9k",
  "dWN0Lm5hbWU7CiAgJCgnY2hlY2tvdXREaXNjb3VudENvZGUnKS52YWx1ZSA9ICcnOwogICQoJ2No",
  "ZWNrb3V0RGlzY291bnRSb3cnKS5zdHlsZS5kaXNwbGF5ID0gJ25vbmUnOwogICQoJ2NoZWNrb3V0",
  "RXJyb3InKS5jbGFzc0xpc3QucmVtb3ZlKCdzaG93Jyk7CiAgdXBkYXRlQ2hlY2tvdXRTdW1tYXJ5",
  "KCk7CiAgJCgnY2hlY2tvdXRNb2RhbEJnJykuY2xhc3NMaXN0LmFkZCgnc2hvdycpOwp9CmZ1bmN0",
  "aW9uIGNsb3NlQ2hlY2tvdXRNb2RhbCgpeyAkKCdjaGVja291dE1vZGFsQmcnKS5jbGFzc0xpc3Qu",
  "cmVtb3ZlKCdzaG93Jyk7IH0KJCgnYnRuQ2xvc2VDaGVja291dCcpLmFkZEV2ZW50TGlzdGVuZXIo",
  "J2NsaWNrJywgY2xvc2VDaGVja291dE1vZGFsKTsKCmZ1bmN0aW9uIHVwZGF0ZUNoZWNrb3V0U3Vt",
  "bWFyeSgpewogIGNvbnN0IGJhc2UgPSBwYXJzZUZsb2F0KFN0cmluZyhjaGVja291dFByb2R1Y3Qu",
  "cHJpY2UpLnJlcGxhY2UoL1teXGQuXS9nLCcnKSkgfHwgMDsKICBjb25zdCBkaXNjb3VudEFtb3Vu",
  "dCA9IE1hdGgucm91bmQoYmFzZSAqIGFwcGxpZWREaXNjb3VudFBlcmNlbnQgLyAxMDApOwogIGNv",
  "bnN0IGZpbmFsID0gYmFzZSAtIGRpc2NvdW50QW1vdW50OwogICQoJ2NoZWNrb3V0T3JpZ2luYWxQ",
  "cmljZScpLnRleHRDb250ZW50ID0gZm10TW9uZXkoYmFzZSk7CiAgaWYoYXBwbGllZERpc2NvdW50",
  "UGVyY2VudCA+IDApewogICAgJCgnY2hlY2tvdXREaXNjb3VudFJvdycpLnN0eWxlLmRpc3BsYXkg",
  "PSAnZmxleCc7CiAgICAkKCdjaGVja291dERpc2NvdW50QW1vdW50JykudGV4dENvbnRlbnQgPSAn",
  "LScgKyBmbXRNb25leShkaXNjb3VudEFtb3VudCkgKyAnICgnICsgYXBwbGllZERpc2NvdW50UGVy",
  "Y2VudCArICclKSc7CiAgfSBlbHNlIHsKICAgICQoJ2NoZWNrb3V0RGlzY291bnRSb3cnKS5zdHls",
  "ZS5kaXNwbGF5ID0gJ25vbmUnOwogIH0KICAkKCdjaGVja291dEZpbmFsUHJpY2UnKS50ZXh0Q29u",
  "dGVudCA9IGZtdE1vbmV5KGZpbmFsKTsKfQoKJCgnYnRuQXBwbHlEaXNjb3VudCcpLmFkZEV2ZW50",
  "TGlzdGVuZXIoJ2NsaWNrJywgYXN5bmMgKCk9PnsKICBjb25zdCBjb2RlID0gJCgnY2hlY2tvdXRE",
  "aXNjb3VudENvZGUnKS52YWx1ZS50cmltKCkudG9VcHBlckNhc2UoKTsKICBjb25zdCBlcnJCb3gg",
  "PSAkKCdjaGVja291dEVycm9yJyk7CiAgZXJyQm94LmNsYXNzTGlzdC5yZW1vdmUoJ3Nob3cnKTsK",
  "ICBpZighY29kZSl7IGFwcGxpZWREaXNjb3VudFBlcmNlbnQgPSAwOyB1cGRhdGVDaGVja291dFN1",
  "bW1hcnkoKTsgcmV0dXJuOyB9CgogIHRyeXsKICAgIGNvbnN0IHJlcyA9IGF3YWl0IGZldGNoKEFQ",
  "SV9CQVNFICsgJy9hcGkvZGlzY291bnQtY2hlY2s/Y29kZT0nICsgZW5jb2RlVVJJQ29tcG9uZW50",
  "KGNvZGUpLCB7IGNhY2hlOiduby1zdG9yZScgfSk7CiAgICBjb25zdCBkYXRhID0gYXdhaXQgcmVz",
  "Lmpzb24oKTsKICAgIGlmKCFkYXRhLnZhbGlkKXsKICAgICAgY29uc3QgbWFwID0gewogICAgICAg",
  "IGRpc2NvdW50X2ludmFsaWQ6ICdNw6MgZ2nhuqNtIGdpw6Ega2jDtG5nIHThu5NuIHThuqFpIGhv",
  "4bq3YyDEkcOjIGLhu4sgdOG6r3QnLAogICAgICAgIGRpc2NvdW50X2V4cGlyZWQ6ICdNw6MgZ2nh",
  "uqNtIGdpw6EgxJHDoyBo4bq/dCBo4bqhbicsCiAgICAgICAgZGlzY291bnRfdXNlZF91cDogJ03D",
  "oyBnaeG6o20gZ2nDoSDEkcOjIGjhur90IGzGsOG7o3Qgc+G7rSBk4bulbmcnCiAgICAgIH07CiAg",
  "ICAgIGFwcGxpZWREaXNjb3VudFBlcmNlbnQgPSAwOwogICAgICB1cGRhdGVDaGVja291dFN1bW1h",
  "cnkoKTsKICAgICAgdGhyb3cgbmV3IEVycm9yKG1hcFtkYXRhLmVycm9yXSB8fCAnTcOjIGdp4bqj",
  "bSBnacOhIGtow7RuZyBo4bujcCBs4buHJyk7CiAgICB9CiAgICBhcHBsaWVkRGlzY291bnRQZXJj",
  "ZW50ID0gZGF0YS5wZXJjZW50OwogICAgdXBkYXRlQ2hlY2tvdXRTdW1tYXJ5KCk7CiAgICBzaG93",
  "VG9hc3QoJ8SQw6Mgw6FwIGThu6VuZyBtw6MgZ2nhuqNtICcgKyBkYXRhLnBlcmNlbnQgKyAnJScp",
  "OwogIH1jYXRjaChlKXsKICAgIGVyckJveC50ZXh0Q29udGVudCA9IGUubWVzc2FnZTsKICAgIGVy",
  "ckJveC5jbGFzc0xpc3QuYWRkKCdzaG93Jyk7CiAgfQp9KTsKCiQoJ2J0bkNvbmZpcm1DaGVja291",
  "dCcpLmFkZEV2ZW50TGlzdGVuZXIoJ2NsaWNrJywgYXN5bmMgKCk9PnsKICBjb25zdCBlcnJCb3gg",
  "PSAkKCdjaGVja291dEVycm9yJyk7CiAgZXJyQm94LmNsYXNzTGlzdC5yZW1vdmUoJ3Nob3cnKTsK",
  "ICBjb25zdCBjb2RlID0gJCgnY2hlY2tvdXREaXNjb3VudENvZGUnKS52YWx1ZS50cmltKCkudG9V",
  "cHBlckNhc2UoKTsKICBjb25zdCBidG4gPSAkKCdidG5Db25maXJtQ2hlY2tvdXQnKTsKICBidG4u",
  "ZGlzYWJsZWQgPSB0cnVlOyBidG4udGV4dENvbnRlbnQgPSAnxJBhbmcgeOG7rSBsw70uLi4nOwoK",
  "ICB0cnl7CiAgICBjb25zdCByZXMgPSBhd2FpdCBmZXRjaChBUElfQkFTRSArICcvYXBpL2NoZWNr",
  "b3V0JywgewogICAgICBtZXRob2Q6J1BPU1QnLCBoZWFkZXJzOnsnQ29udGVudC1UeXBlJzonYXBw",
  "bGljYXRpb24vanNvbid9LAogICAgICBib2R5OiBKU09OLnN0cmluZ2lmeSh7IHRva2VuOiBjdXN0",
  "b21lclRva2VuLCBwcm9kdWN0SWQ6IGNoZWNrb3V0UHJvZHVjdC5pZCwgZGlzY291bnRDb2RlOiBj",
  "b2RlIH0pCiAgICB9KTsKICAgIGNvbnN0IGRhdGEgPSBhd2FpdCByZXMuanNvbigpOwogICAgaWYo",
  "IXJlcy5vayB8fCAhZGF0YS5vayl7CiAgICAgIGNvbnN0IG1hcCA9IHsKICAgICAgICBub3RfbG9n",
  "Z2VkX2luOiAnUGhpw6puIMSRxINuZyBuaOG6rXAgxJHDoyBo4bq/dCBo4bqhbiwgdnVpIGzDsm5n",
  "IMSRxINuZyBuaOG6rXAgbOG6oWknLAogICAgICAgIHByb2R1Y3Rfbm90X2ZvdW5kOiAnU+G6o24g",
  "cGjhuqltIGtow7RuZyBjw7JuIHThu5NuIHThuqFpJywKICAgICAgICBkaXNjb3VudF9pbnZhbGlk",
  "OiAnTcOjIGdp4bqjbSBnacOhIGtow7RuZyBo4bujcCBs4buHJywKICAgICAgICBkaXNjb3VudF9l",
  "eHBpcmVkOiAnTcOjIGdp4bqjbSBnacOhIMSRw6MgaOG6v3QgaOG6oW4nLAogICAgICAgIGRpc2Nv",
  "dW50X3VzZWRfdXA6ICdNw6MgZ2nhuqNtIGdpw6EgxJHDoyBo4bq/dCBsxrDhu6N0IHPhu60gZOG7",
  "pW5nJywKICAgICAgICBvdXRfb2Zfc3RvY2s6ICdT4bqjbiBwaOG6qW0gduG7q2EgaOG6v3QgaMOg",
  "bmcsIHZ1aSBsw7JuZyB0aOG7rSBs4bqhaSBzYXUnCiAgICAgIH07CiAgICAgIHRocm93IG5ldyBF",
  "cnJvcihtYXBbZGF0YS5lcnJvcl0gfHwgJ011YSBrZXkgdGjhuqV0IGLhuqFpLCB2dWkgbMOybmcg",
  "dGjhu60gbOG6oWknKTsKICAgIH0KCiAgICBjbG9zZUNoZWNrb3V0TW9kYWwoKTsKICAgICQoJ3Jl",
  "c3VsdEtleVZhbHVlJykudGV4dENvbnRlbnQgPSBkYXRhLmtleTsKICAgIGxldCBleHBpcnlUeHQ7",
  "CiAgICBpZihkYXRhLmhhc0V4cGlyeVBsYW4gJiYgIWRhdGEuYWN0aXZhdGVkKXsKICAgICAgY29u",
  "c3QgdW5pdExhYmVsID0gZGF0YS5leHBpcnlVbml0PT09J2hvdXInID8gJ2dp4budJyA6IGRhdGEu",
  "ZXhwaXJ5VW5pdD09PSdtb250aCcgPyAndGjDoW5nJyA6ICduZ8OgeSc7CiAgICAgIGV4cGlyeVR4",
  "dCA9IGBDaMawYSBrw61jaCBob+G6oXQgKHPhur0gZMO5bmcgxJHGsOG7o2MgJHtkYXRhLmV4cGly",
  "eUFtb3VudHx8Jz8nfSAke3VuaXRMYWJlbH0ga+G7gyB04burIGzhuqduIMSR4bqndSBz4butIGTh",
  "u6VuZyBrZXkpYDsKICAgIH0gZWxzZSB7CiAgICAgIGV4cGlyeVR4dCA9IGRhdGEuZXhwaXJlc0F0",
  "ID8gbmV3IERhdGUoZGF0YS5leHBpcmVzQXQpLnRvTG9jYWxlU3RyaW5nKCd2aS1WTicpIDogJ0to",
  "w7RuZyBnaeG7m2kgaOG6oW4nOwogICAgfQogICAgJCgncmVzdWx0S2V5TWV0YScpLnRleHRDb250",
  "ZW50ID0gYEjhuqFuIGTDuW5nOiAke2V4cGlyeVR4dH0gwrcgU+G7kSB0aGnhur90IGLhu4sgY2hv",
  "IHBow6lwOiAke2RhdGEubWF4RGV2aWNlc3x8MX0gwrcgxJDDoyB0aGFuaCB0b8OhbjogJHtmbXRN",
  "b25leShkYXRhLnByaWNlUGFpZCl9YDsKICAgICQoJ3Jlc3VsdE1vZGFsQmcnKS5jbGFzc0xpc3Qu",
  "YWRkKCdzaG93Jyk7CiAgICBsb2FkUHJvZHVjdHMoKTsKICB9Y2F0Y2goZSl7CiAgICBlcnJCb3gu",
  "dGV4dENvbnRlbnQgPSBlLm1lc3NhZ2U7CiAgICBlcnJCb3guY2xhc3NMaXN0LmFkZCgnc2hvdycp",
  "OwogIH1maW5hbGx5ewogICAgYnRuLmRpc2FibGVkID0gZmFsc2U7IGJ0bi50ZXh0Q29udGVudCA9",
  "ICdYw6FjIG5o4bqtbiBtdWEnOwogIH0KfSk7CgovKiAtLS0tLS0tLS0tIE1vZGFsIEvhur90IHF1",
  "4bqjIC0tLS0tLS0tLS0gKi8KJCgnYnRuQ2xvc2VSZXN1bHQnKS5hZGRFdmVudExpc3RlbmVyKCdj",
  "bGljaycsICgpPT4gJCgncmVzdWx0TW9kYWxCZycpLmNsYXNzTGlzdC5yZW1vdmUoJ3Nob3cnKSk7",
  "CiQoJ2J0bkNvcHlSZXN1bHRLZXknKS5hZGRFdmVudExpc3RlbmVyKCdjbGljaycsICgpPT57CiAg",
  "Y29uc3QgdmFsID0gJCgncmVzdWx0S2V5VmFsdWUnKS50ZXh0Q29udGVudDsKICBuYXZpZ2F0b3Iu",
  "Y2xpcGJvYXJkLndyaXRlVGV4dCh2YWwpLnRoZW4oKCk9PiBzaG93VG9hc3QoJ8SQw6Mgc2FvIGNo",
  "w6lwIGtleScpKS5jYXRjaCgoKT0+IHNob3dUb2FzdCgnS2jDtG5nIHNhbyBjaMOpcCDEkcaw4buj",
  "YywgdnVpIGzDsm5nIGNvcHkgdGjhu6cgY8O0bmcnKSk7Cn0pOwoKLyogLS0tLS0tLS0tLSBNb2Rh",
  "bCBjaOG7jW4gZ8OzaSBI4buiUCBOSOG6pFQgKGTDuW5nIGNodW5nIGNobyBHZXRLZXkgJiBz4bqj",
  "biBwaOG6qW0gbXVhIGLhurFuZyB0aeG7gW4pIC0tLS0tLS0tLS0KICAgb3B0aW9uczogW3tpZCwg",
  "aWNvbiwgbGFiZWwsIHN1YiwgcHJpY2UobnVsbGFibGUpLCBpblN0b2NrLCB0YWd9XQogICAtIHBy",
  "aWNlID09PSBudWxsfHVuZGVmaW5lZCAgLT4gaGnhu4NuIHRo4buLICJsxrDhu6N0IHbGsOG7o3Qg",
  "bGluayIgdGhheSB2w6wgZ2nDoSAoZMO5bmcgY2hvIEdldEtleSkKICAgLSBvblNlbGVjdChvcHRp",
  "b25JZCkgxJHGsOG7o2MgZ+G7jWkga2hpIGtow6FjaCBi4bqlbSB2w6BvIDEgZ8OzaSBjw7JuIGjD",
  "oG5nLiAtLS0tLS0tLS0tICovCmxldCB1bmlmaWVkUGxhbk9uU2VsZWN0ID0gbnVsbDsKCmZ1bmN0",
  "aW9uIG9wZW5VbmlmaWVkUGxhbk1vZGFsKHsgbG9nbywgdGl0bGUsIHN1YnRpdGxlLCBvcHRpb25z",
  "LCBvblNlbGVjdCB9KXsKICAkKCd1bmlmaWVkUGxhbkxvZ28nKS5pbm5lckhUTUwgPSBsb2dvID8g",
  "YDxpbWcgc3JjPSIke2xvZ299Ij5gIDogJ/Cfk6YnOwogICQoJ3VuaWZpZWRQbGFuVGl0bGUnKS50",
  "ZXh0Q29udGVudCA9IHRpdGxlIHx8ICfigJQnOwogICQoJ3VuaWZpZWRQbGFuU3VidGl0bGUnKS50",
  "ZXh0Q29udGVudCA9IHN1YnRpdGxlIHx8ICcnOwogICQoJ3VuaWZpZWRQbGFuRXJyb3InKS5jbGFz",
  "c0xpc3QucmVtb3ZlKCdzaG93Jyk7CiAgdW5pZmllZFBsYW5PblNlbGVjdCA9IG9uU2VsZWN0OwoK",
  "ICBjb25zdCBsaXN0ID0gJCgndW5pZmllZFBsYW5MaXN0Jyk7CiAgbGlzdC5pbm5lckhUTUwgPSAn",
  "JzsKICAob3B0aW9uc3x8W10pLmZvckVhY2gob3B0PT57CiAgICBjb25zdCBidG4gPSBkb2N1bWVu",
  "dC5jcmVhdGVFbGVtZW50KCdidXR0b24nKTsKICAgIGJ0bi5jbGFzc05hbWUgPSAncGxhbi1vcHRp",
  "b24nOwogICAgYnRuLmRpc2FibGVkID0gIW9wdC5pblN0b2NrOwogICAgY29uc3QgcHJpY2VIdG1s",
  "ID0gKG9wdC5wcmljZT09PW51bGwgfHwgb3B0LnByaWNlPT09dW5kZWZpbmVkKQogICAgICA/IGA8",
  "ZGl2IGNsYXNzPSJwcmljZSI+JHtvcHQuc3RvY2tMYWJlbCB8fCAnJ308L2Rpdj5gCiAgICAgIDog",
  "YDxkaXYgY2xhc3M9InByaWNlIj4ke2ZtdE1vbmV5KG9wdC5wcmljZSl9PC9kaXY+YDsKICAgIGJ0",
  "bi5pbm5lckhUTUwgPSBgCiAgICAgIDxkaXYgY2xhc3M9Imljb24iPiR7b3B0Lmljb24gfHwgJ/Cf",
  "lJEnfTwvZGl2PgogICAgICA8ZGl2IGNsYXNzPSJpbmZvIj4KICAgICAgICA8ZGl2IGNsYXNzPSJs",
  "YmwiPiR7b3B0LmxhYmVsfTwvZGl2PgogICAgICAgICR7b3B0LnN1YiA/IGA8ZGl2IGNsYXNzPSJz",
  "dWIzIj4ke29wdC5zdWJ9PC9kaXY+YCA6ICcnfQogICAgICA8L2Rpdj4KICAgICAgPGRpdiBjbGFz",
  "cz0icmlnaHQiPgogICAgICAgICR7cHJpY2VIdG1sfQogICAgICAgICR7b3B0LnRhZyA/IGA8ZGl2",
  "IGNsYXNzPSJ0YWciPiR7b3B0LnRhZ308L2Rpdj5gIDogKCFvcHQuaW5TdG9jayA/IGA8ZGl2IGNs",
  "YXNzPSJ0YWciIHN0eWxlPSJjb2xvcjp2YXIoLS1kYW5nZXIpOyI+SOG6vlQgSMOATkc8L2Rpdj5g",
  "IDogJycpfQogICAgICA8L2Rpdj4KICAgIGA7CiAgICBpZihvcHQuaW5TdG9jayl7CiAgICAgIGJ0",
  "bi5hZGRFdmVudExpc3RlbmVyKCdjbGljaycsICgpPT57CiAgICAgICAgZG9jdW1lbnQucXVlcnlT",
  "ZWxlY3RvckFsbCgnI3VuaWZpZWRQbGFuTGlzdCAucGxhbi1vcHRpb24nKS5mb3JFYWNoKGVsPT5l",
  "bC5jbGFzc0xpc3QucmVtb3ZlKCdzZWxlY3RlZCcpKTsKICAgICAgICBidG4uY2xhc3NMaXN0LmFk",
  "ZCgnc2VsZWN0ZWQnKTsKICAgICAgICBpZih1bmlmaWVkUGxhbk9uU2VsZWN0KSB1bmlmaWVkUGxh",
  "bk9uU2VsZWN0KG9wdC5pZCk7CiAgICAgIH0pOwogICAgfQogICAgbGlzdC5hcHBlbmRDaGlsZChi",
  "dG4pOwogIH0pOwogICQoJ3VuaWZpZWRQbGFuTW9kYWxCZycpLmNsYXNzTGlzdC5hZGQoJ3Nob3cn",
  "KTsKfQpmdW5jdGlvbiBjbG9zZVVuaWZpZWRQbGFuTW9kYWwoKXsgJCgndW5pZmllZFBsYW5Nb2Rh",
  "bEJnJykuY2xhc3NMaXN0LnJlbW92ZSgnc2hvdycpOyB9CiQoJ2J0bkNsb3NlVW5pZmllZFBsYW4n",
  "KS5hZGRFdmVudExpc3RlbmVyKCdjbGljaycsIGNsb3NlVW5pZmllZFBsYW5Nb2RhbCk7CgovKiAt",
  "LS0tLS0tLS0tIE5ow7NtIHPhuqNuIHBo4bqpbSAoMSBsb2dvL3TDqm4gKyBuaGnhu4F1IGfDs2kg",
  "Z2nDoSwgZ2nhu5FuZyBHZXRLZXkpIC0tLS0tLS0tLS0gKi8KbGV0IHByb2R1Y3RHcm91cHMgPSBb",
  "XTsKbGV0IHBlbmRpbmdCdXlHcm91cElkID0gbnVsbDsgLy8gbmjDs20gc+G6o24gcGjhuqltIGto",
  "w6FjaCBi4bqlbSB2w6BvIHRyxrDhu5tjIGtoaSDEkcSDbmcgbmjhuq1wIHhvbmcKbGV0IGFjdGl2",
  "ZVBnR3JvdXAgPSBudWxsOwoKYXN5bmMgZnVuY3Rpb24gbG9hZFByb2R1Y3RHcm91cHMoKXsKICB0",
  "cnl7CiAgICBjb25zdCByZXMgPSBhd2FpdCBmZXRjaChBUElfQkFTRSArICcvYXBpL3Byb2R1Y3Qt",
  "Z3JvdXBzJywgeyBjYWNoZTonbm8tc3RvcmUnIH0pOwogICAgcHJvZHVjdEdyb3VwcyA9IGF3YWl0",
  "IHJlcy5qc29uKCk7CiAgfWNhdGNoKGUpewogICAgY29uc29sZS53YXJuKCdbS2V5VmF1bHQgU3Rv",
  "cmVdIEtow7RuZyB04bqjaSDEkcaw4bujYyBkYW5oIHPDoWNoIG5ow7NtIHPhuqNuIHBo4bqpbScs",
  "IGUpOwogICAgcHJvZHVjdEdyb3VwcyA9IFtdOwogIH0KICByZW5kZXJQcm9kdWN0R3JvdXBzKCk7",
  "Cn0KCmZ1bmN0aW9uIGZtdFBnUGxhbkR1cmF0aW9uKHBsKXsKICBpZihwbC51bml0PT09J3VubGlt",
  "aXRlZCcgfHwgIXBsLmFtb3VudCkgcmV0dXJuICdLaMO0bmcgZ2nhu5tpIGjhuqFuJzsKICBjb25z",
  "dCB1bml0TGFiZWwgPSBwbC51bml0PT09J2hvdXInID8gJ2dp4budJyA6IHBsLnVuaXQ9PT0nbW9u",
  "dGgnID8gJ3Row6FuZycgOiAnbmfDoHknOwogIHJldHVybiBwbC5hbW91bnQgKyAnICcgKyB1bml0",
  "TGFiZWw7Cn0KCmZ1bmN0aW9uIHJlbmRlclByb2R1Y3RHcm91cHMoKXsKICBjb25zdCBncmlkID0g",
  "JCgncGdHcmlkJyk7CiAgZ3JpZC5pbm5lckhUTUwgPSAnJzsKICBwcm9kdWN0R3JvdXBzLmZvckVh",
  "Y2goZz0+ewogICAgY29uc3QgdG90YWxTdG9jayA9IChnLnBsYW5zfHxbXSkucmVkdWNlKChzdW0s",
  "cCk9PiBzdW0gKyAocC5zdG9ja3x8MCksIDApOwogICAgY29uc3QgbWluUHJpY2UgPSAoZy5wbGFu",
  "c3x8W10pLnJlZHVjZSgobWluLHApPT4gTWF0aC5taW4obWluLCBOdW1iZXIocC5wcmljZSl8fElu",
  "ZmluaXR5KSwgSW5maW5pdHkpOwogICAgY29uc3QgY2FyZCA9IGRvY3VtZW50LmNyZWF0ZUVsZW1l",
  "bnQoJ2RpdicpOwogICAgY2FyZC5jbGFzc05hbWUgPSAnY2FyZCc7CiAgICBjYXJkLmlubmVySFRN",
  "TCA9IGAKICAgICAgPGRpdiBjbGFzcz0ibG9nbyI+JHtnLmxvZ28gPyBgPGltZyBzcmM9IiR7Zy5s",
  "b2dvfSI+YCA6ICfwn5OmJ308L2Rpdj4KICAgICAgPGgzPiR7Zy5uYW1lfTwvaDM+CiAgICAgIDxk",
  "aXYgY2xhc3M9Im1ldGEiPgogICAgICAgIDxzcGFuPiR7KGcucGxhbnN8fFtdKS5sZW5ndGh9IGfD",
  "s2kgZ2nDoSDCtyB04burIDxiPiR7TnVtYmVyLmlzRmluaXRlKG1pblByaWNlKSA/IGZtdE1vbmV5",
  "KG1pblByaWNlKSA6ICfigJQnfTwvYj48L3NwYW4+CiAgICAgICAgPHNwYW4gY2xhc3M9InN0b2Nr",
  "ICR7dG90YWxTdG9jaz4wID8gJ2luJyA6ICdvdXQnfSI+JHt0b3RhbFN0b2NrPjAgPyAn4pyUIEPD",
  "sm4gJyt0b3RhbFN0b2NrKycga2V5JyA6ICfinJYgSOG6v3QgaMOgbmcnfTwvc3Bhbj4KICAgICAg",
  "PC9kaXY+CiAgICAgIDxidXR0b24gY2xhc3M9ImJ0biBidXktYnRuIiBkYXRhLWdpZD0iJHtnLmlk",
  "fSI+TXVhIEtleTwvYnV0dG9uPgogICAgYDsKICAgIGdyaWQuYXBwZW5kQ2hpbGQoY2FyZCk7CiAg",
  "fSk7Cn0KCiQoJ3BnR3JpZCcpLmFkZEV2ZW50TGlzdGVuZXIoJ2NsaWNrJywgKGUpPT57CiAgY29u",
  "c3QgYnRuID0gZS50YXJnZXQuY2xvc2VzdCgnLmJ1eS1idG4nKTsKICBpZighYnRuKSByZXR1cm47",
  "CiAgY29uc3QgZ2lkID0gYnRuLmRhdGFzZXQuZ2lkOwogIGlmKCFjdXN0b21lclRva2VuKXsKICAg",
  "IHBlbmRpbmdCdXlHcm91cElkID0gZ2lkOwogICAgb3BlbkF1dGhNb2RhbCgpOwogICAgcmV0dXJu",
  "OwogIH0KICBvcGVuUGdQbGFuTW9kYWwoZ2lkKTsKfSk7CgovKiBN4bufIG1vZGFsIGNo4buNbiBn",
  "w7NpIEjhu6JQIE5I4bqkVCBjaG8gMSBOaMOzbSBz4bqjbiBwaOG6qW0gKG11YSBi4bqxbmcgdGnh",
  "u4FuLCB0aGFuaCB0b8OhbiBuZ2F5KS4gKi8KZnVuY3Rpb24gb3BlblBnUGxhbk1vZGFsKGdyb3Vw",
  "SWQpewogIGFjdGl2ZVBnR3JvdXAgPSBwcm9kdWN0R3JvdXBzLmZpbmQoZz0+Zy5pZD09PWdyb3Vw",
  "SWQpOwogIGlmKCFhY3RpdmVQZ0dyb3VwKXsgc2hvd1RvYXN0KCdT4bqjbiBwaOG6qW0ga2jDtG5n",
  "IGPDsm4gdOG7k24gdOG6oWksIHZ1aSBsw7JuZyB04bqjaSBs4bqhaSB0cmFuZycpOyByZXR1cm47",
  "IH0KICBvcGVuVW5pZmllZFBsYW5Nb2RhbCh7CiAgICBtb2RlOiAncHJvZHVjdCcsCiAgICBsb2dv",
  "OiBhY3RpdmVQZ0dyb3VwLmxvZ28sCiAgICB0aXRsZTogYWN0aXZlUGdHcm91cC5uYW1lLAogICAg",
  "c3VidGl0bGU6ICdDaOG7jW4gZ8OzaSBi4bqhbiBtdeG7kW4gbXVhLiBUaGFuaCB0b8OhbiBuZ2F5",
  "IGLhurFuZyBz4buRIGTGsCB0w6BpIGtob+G6o24uJywKICAgIG9wdGlvbnM6IChhY3RpdmVQZ0dy",
  "b3VwLnBsYW5zfHxbXSkubWFwKHBsPT4oewogICAgICBpZDogcGwuaWQsCiAgICAgIGljb246ICfw",
  "n5SRJywKICAgICAgbGFiZWw6IGZtdFBnUGxhbkR1cmF0aW9uKHBsKSwKICAgICAgc3ViOiBwbC5s",
  "YWJlbCAmJiBwbC5sYWJlbCAhPT0gZm10UGdQbGFuRHVyYXRpb24ocGwpID8gcGwubGFiZWwgOiAo",
  "cGwudW5pdD09PSd1bmxpbWl0ZWQnID8gJ1bEqW5oIHZp4buFbicgOiAnQ8OzIHRo4budaSBo4bqh",
  "bicpLAogICAgICBwcmljZTogcGwucHJpY2UsCiAgICAgIGluU3RvY2s6IChwbC5zdG9ja3x8MCkg",
  "PiAwLAogICAgICB0YWc6IG51bGwKICAgIH0pKSwKICAgIG9uU2VsZWN0OiAocGxhbklkKT0+ewog",
  "ICAgICBjbG9zZVVuaWZpZWRQbGFuTW9kYWwoKTsKICAgICAgb3BlblBnQ2hlY2tvdXRNb2RhbChh",
  "Y3RpdmVQZ0dyb3VwLmlkLCBwbGFuSWQpOwogICAgfQogIH0pOwp9CgoKLyogLS0tLS0tLS0tLSBU",
  "aGFuaCB0b8OhbiAxIGfDs2kgdHJvbmcgTmjDs20gc+G6o24gcGjhuqltIChkw7luZyBs4bqhaSBt",
  "b2RhbCB0aGFuaCB0b8OhbiBjaHVuZykgLS0tLS0tLS0tLSAqLwpsZXQgY2hlY2tvdXRHcm91cElk",
  "ID0gbnVsbDsKbGV0IGNoZWNrb3V0UGxhbklkID0gbnVsbDsKCmZ1bmN0aW9uIG9wZW5QZ0NoZWNr",
  "b3V0TW9kYWwoZ3JvdXBJZCwgcGxhbklkKXsKICBjb25zdCBncm91cCA9IHByb2R1Y3RHcm91cHMu",
  "ZmluZChnPT5nLmlkPT09Z3JvdXBJZCk7CiAgY29uc3QgcGxhbiA9IGdyb3VwICYmIChncm91cC5w",
  "bGFuc3x8W10pLmZpbmQocD0+cC5pZD09PXBsYW5JZCk7CiAgaWYoIWdyb3VwIHx8ICFwbGFuKXsg",
  "c2hvd1RvYXN0KCdHw7NpIHPhuqNuIHBo4bqpbSBraMO0bmcgY8OybiB04buTbiB04bqhaSwgdnVp",
  "IGzDsm5nIHThuqNpIGzhuqFpIHRyYW5nJyk7IHJldHVybjsgfQogIGNoZWNrb3V0R3JvdXBJZCA9",
  "IGdyb3VwSWQ7CiAgY2hlY2tvdXRQbGFuSWQgPSBwbGFuSWQ7CiAgY2hlY2tvdXRQcm9kdWN0ID0g",
  "eyBuYW1lOiBgJHtncm91cC5uYW1lfSDigJQgJHtmbXRQZ1BsYW5EdXJhdGlvbihwbGFuKX1gLCBw",
  "cmljZTogcGxhbi5wcmljZSB9OyAvLyB0w6FpIGTDuW5nIGJp4bq/biBjaGVja291dFByb2R1Y3Qg",
  "Y2hvIHBo4bqnbiBoaeG7g24gdGjhu4sgdMOzbSB04bqvdCBnacOhCiAgYXBwbGllZERpc2NvdW50",
  "UGVyY2VudCA9IDA7CiAgJCgnY2hlY2tvdXRQcm9kdWN0TmFtZScpLnRleHRDb250ZW50ID0gY2hl",
  "Y2tvdXRQcm9kdWN0Lm5hbWU7CiAgJCgnY2hlY2tvdXREaXNjb3VudENvZGUnKS52YWx1ZSA9ICcn",
  "OwogICQoJ2NoZWNrb3V0RGlzY291bnRSb3cnKS5zdHlsZS5kaXNwbGF5ID0gJ25vbmUnOwogICQo",
  "J2NoZWNrb3V0RXJyb3InKS5jbGFzc0xpc3QucmVtb3ZlKCdzaG93Jyk7CiAgdXBkYXRlQ2hlY2tv",
  "dXRTdW1tYXJ5KCk7CiAgJCgnY2hlY2tvdXRNb2RhbEJnJykuY2xhc3NMaXN0LmFkZCgnc2hvdycp",
  "Owp9CgovKiBH4bqvbiB0aMOqbSB2w6BvIG7DunQgIljDoWMgbmjhuq1uIG11YSIgxJHDoyBjw7Mg",
  "c+G6tW46IG7hur91IMSRYW5nIG11YSB0aGVvIE5ow7NtIHPhuqNuIHBo4bqpbSAoY2hlY2tvdXRH",
  "cm91cElkCiAgIMSRxrDhu6NjIHNldCkgdGjDrCBn4buNaSAvYXBpL2NoZWNrb3V0LWdyb3VwIHRo",
  "YXkgdsOsIC9hcGkvY2hlY2tvdXQ7IG5nxrDhu6NjIGzhuqFpIGdp4buvIG5ndXnDqm4gaMOgbmgg",
  "dmkgY8WpLiAqLwpjb25zdCBidG5Db25maXJtQ2hlY2tvdXRFbCA9ICQoJ2J0bkNvbmZpcm1DaGVj",
  "a291dCcpOwpjb25zdCBvcmlnaW5hbENvbmZpcm1DaGVja291dEhhbmRsZXJzID0gW107IC8vIGto",
  "w7RuZyB4b8OhIGhhbmRsZXIgY8WpIOKAlCBjaOG7iSBjaOG6t24gbsOzIGNo4bqheSBraGkgxJFh",
  "bmcg4bufIGx14buTbmcgbmjDs20gc+G6o24gcGjhuqltCmJ0bkNvbmZpcm1DaGVja291dEVsLmFk",
  "ZEV2ZW50TGlzdGVuZXIoJ2NsaWNrJywgYXN5bmMgKGUpPT57CiAgaWYoIWNoZWNrb3V0R3JvdXBJ",
  "ZCkgcmV0dXJuOyAvLyBsdeG7k25nIHPhuqNuIHBo4bqpbSDEkcahbiBs4bq7IGPFqSB04buxIHjh",
  "u60gbMO9IHF1YSBoYW5kbGVyIMSRw6MgxJHEg25nIGvDvSB0csaw4bubYyDEkcOzCiAgZS5zdG9w",
  "SW1tZWRpYXRlUHJvcGFnYXRpb24oKTsKICBjb25zdCBlcnJCb3ggPSAkKCdjaGVja291dEVycm9y",
  "Jyk7CiAgZXJyQm94LmNsYXNzTGlzdC5yZW1vdmUoJ3Nob3cnKTsKICBjb25zdCBjb2RlID0gJCgn",
  "Y2hlY2tvdXREaXNjb3VudENvZGUnKS52YWx1ZS50cmltKCkudG9VcHBlckNhc2UoKTsKICBjb25z",
  "dCBidG4gPSAkKCdidG5Db25maXJtQ2hlY2tvdXQnKTsKICBidG4uZGlzYWJsZWQgPSB0cnVlOyBi",
  "dG4udGV4dENvbnRlbnQgPSAnxJBhbmcgeOG7rSBsw70uLi4nOwoKICB0cnl7CiAgICBjb25zdCBy",
  "ZXMgPSBhd2FpdCBmZXRjaChBUElfQkFTRSArICcvYXBpL2NoZWNrb3V0LWdyb3VwJywgewogICAg",
  "ICBtZXRob2Q6J1BPU1QnLCBoZWFkZXJzOnsnQ29udGVudC1UeXBlJzonYXBwbGljYXRpb24vanNv",
  "bid9LAogICAgICBib2R5OiBKU09OLnN0cmluZ2lmeSh7IHRva2VuOiBjdXN0b21lclRva2VuLCBn",
  "cm91cElkOiBjaGVja291dEdyb3VwSWQsIHBsYW5JZDogY2hlY2tvdXRQbGFuSWQsIGRpc2NvdW50",
  "Q29kZTogY29kZSB9KQogICAgfSk7CiAgICBjb25zdCBkYXRhID0gYXdhaXQgcmVzLmpzb24oKTsK",
  "ICAgIGlmKCFyZXMub2sgfHwgIWRhdGEub2spewogICAgICBjb25zdCBtYXAgPSB7CiAgICAgICAg",
  "bm90X2xvZ2dlZF9pbjogJ1BoacOqbiDEkcSDbmcgbmjhuq1wIMSRw6MgaOG6v3QgaOG6oW4sIHZ1",
  "aSBsw7JuZyDEkcSDbmcgbmjhuq1wIGzhuqFpJywKICAgICAgICBncm91cF9ub3RfZm91bmQ6ICdT",
  "4bqjbiBwaOG6qW0ga2jDtG5nIGPDsm4gdOG7k24gdOG6oWknLAogICAgICAgIHBsYW5fbm90X2Zv",
  "dW5kOiAnR8OzaSBz4bqjbiBwaOG6qW0ga2jDtG5nIGPDsm4gdOG7k24gdOG6oWknLAogICAgICAg",
  "IGRpc2NvdW50X2ludmFsaWQ6ICdNw6MgZ2nhuqNtIGdpw6Ega2jDtG5nIGjhu6NwIGzhu4cnLAog",
  "ICAgICAgIGRpc2NvdW50X2V4cGlyZWQ6ICdNw6MgZ2nhuqNtIGdpw6EgxJHDoyBo4bq/dCBo4bqh",
  "bicsCiAgICAgICAgZGlzY291bnRfdXNlZF91cDogJ03DoyBnaeG6o20gZ2nDoSDEkcOjIGjhur90",
  "IGzGsOG7o3Qgc+G7rSBk4bulbmcnLAogICAgICAgIGluc3VmZmljaWVudF9iYWxhbmNlOiAnU+G7",
  "kSBkxrAga2jDtG5nIMSR4bunIMSR4buDIG11YSBnw7NpIG7DoHknLAogICAgICAgIG91dF9vZl9z",
  "dG9jazogJ0fDs2kgbsOgeSB24burYSBo4bq/dCBow6BuZywgdnVpIGzDsm5nIHRo4butIGzhuqFp",
  "IHNhdScKICAgICAgfTsKICAgICAgdGhyb3cgbmV3IEVycm9yKG1hcFtkYXRhLmVycm9yXSB8fCAn",
  "TXVhIGtleSB0aOG6pXQgYuG6oWksIHZ1aSBsw7JuZyB0aOG7rSBs4bqhaScpOwogICAgfQoKICAg",
  "IGNsb3NlQ2hlY2tvdXRNb2RhbCgpOwogICAgY2hlY2tvdXRHcm91cElkID0gbnVsbDsgY2hlY2tv",
  "dXRQbGFuSWQgPSBudWxsOwogICAgJCgncmVzdWx0S2V5VmFsdWUnKS50ZXh0Q29udGVudCA9IGRh",
  "dGEua2V5OwogICAgbGV0IGV4cGlyeVR4dDsKICAgIGlmKGRhdGEuaGFzRXhwaXJ5UGxhbiAmJiAh",
  "ZGF0YS5hY3RpdmF0ZWQpewogICAgICBjb25zdCB1bml0TGFiZWwgPSBkYXRhLmV4cGlyeVVuaXQ9",
  "PT0naG91cicgPyAnZ2nhu50nIDogZGF0YS5leHBpcnlVbml0PT09J21vbnRoJyA/ICd0aMOhbmcn",
  "IDogJ25nw6B5JzsKICAgICAgZXhwaXJ5VHh0ID0gYENoxrBhIGvDrWNoIGhv4bqhdCAoc+G6vSBk",
  "w7luZyDEkcaw4bujYyAke2RhdGEuZXhwaXJ5QW1vdW50fHwnPyd9ICR7dW5pdExhYmVsfSBr4buD",
  "IHThu6sgbOG6p24gxJHhuqd1IHPhu60gZOG7pW5nIGtleSlgOwogICAgfSBlbHNlIHsKICAgICAg",
  "ZXhwaXJ5VHh0ID0gZGF0YS5leHBpcmVzQXQgPyBuZXcgRGF0ZShkYXRhLmV4cGlyZXNBdCkudG9M",
  "b2NhbGVTdHJpbmcoJ3ZpLVZOJykgOiAnS2jDtG5nIGdp4bubaSBo4bqhbic7CiAgICB9CiAgICAk",
  "KCdyZXN1bHRLZXlNZXRhJykudGV4dENvbnRlbnQgPSBgSOG6oW4gZMO5bmc6ICR7ZXhwaXJ5VHh0",
  "fSDCtyBT4buRIHRoaeG6v3QgYuG7iyBjaG8gcGjDqXA6ICR7ZGF0YS5tYXhEZXZpY2VzfHwxfSDC",
  "tyDEkMOjIHRoYW5oIHRvw6FuOiAke2ZtdE1vbmV5KGRhdGEucHJpY2VQYWlkKX1gOwogICAgJCgn",
  "cmVzdWx0TW9kYWxCZycpLmNsYXNzTGlzdC5hZGQoJ3Nob3cnKTsKICAgIGxvYWRQcm9kdWN0R3Jv",
  "dXBzKCk7CiAgfWNhdGNoKGUpewogICAgZXJyQm94LnRleHRDb250ZW50ID0gZS5tZXNzYWdlOwog",
  "ICAgZXJyQm94LmNsYXNzTGlzdC5hZGQoJ3Nob3cnKTsKICB9ZmluYWxseXsKICAgIGJ0bi5kaXNh",
  "YmxlZCA9IGZhbHNlOyBidG4udGV4dENvbnRlbnQgPSAnWMOhYyBuaOG6rW4gbXVhJzsKICB9Cn0s",
  "IHRydWUpOyAvLyBjYXB0dXJlOnRydWUgxJHhu4MgY2jhuqF5IFRSxq/hu5pDIGhhbmRsZXIgY8Wp",
  "IHbDoCBjw7MgdGjhu4MgY2jhurduIG7DsyBi4bqxbmcgc3RvcEltbWVkaWF0ZVByb3BhZ2F0aW9u",
  "IGtoaSBj4bqnbgoKLyogxJDhuqNtIGLhuqNvIMSRw7NuZyBtb2RhbCB0aGFuaCB0b8OhbiBjxalu",
  "ZyBsdcO0biByZXNldCB0cuG6oW5nIHRow6FpICLEkWFuZyBtdWEgdGhlbyBuaMOzbSBz4bqjbiBw",
  "aOG6qW0iLiAqLwokKCdidG5DbG9zZUNoZWNrb3V0JykuYWRkRXZlbnRMaXN0ZW5lcignY2xpY2sn",
  "LCAoKT0+eyBjaGVja291dEdyb3VwSWQgPSBudWxsOyBjaGVja291dFBsYW5JZCA9IG51bGw7IH0p",
  "OwoKbG9hZFByb2R1Y3RHcm91cHMoKTsKCi8qIC0tLS0tLS0tLS0gQ2jhu6ljIG7Eg25nIEdFVEtF",
  "WSAodsaw4bujdCBsaW5rIG5o4bqtbiBrZXkpIC0tLS0tLS0tLS0gKi8KbGV0IGdrR2FtZXMgPSBb",
  "XTsKbGV0IGdrU2VsZWN0ZWRHYW1lID0gbnVsbDsKbGV0IGdrU2VsZWN0ZWREdXJhdGlvbiA9IG51",
  "bGw7CmxldCBna1Nlc3Npb25JZCA9IG51bGw7CmxldCBna1RvdGFsUm91bmRzID0gMDsKbGV0IGdr",
  "Q3VycmVudFJvdW5kID0gMDsKCiQoJ2RkR2V0S2V5JykuYWRkRXZlbnRMaXN0ZW5lcignY2xpY2sn",
  "LCAoKT0+ewogIGNsb3NlRHJvcGRvd24oKTsKICBvcGVuR2tDaG9vc2VHYW1lTW9kYWwoKTsKfSk7",
  "Cgphc3luYyBmdW5jdGlvbiBvcGVuR2tDaG9vc2VHYW1lTW9kYWwoKXsKICAkKCdna0Nob29zZUdh",
  "bWVNb2RhbEJnJykuY2xhc3NMaXN0LmFkZCgnc2hvdycpOwogICQoJ2drR2FtZUdyaWQnKS5pbm5l",
  "ckhUTUwgPSAnPGRpdiBjbGFzcz0iaGlzdG9yeS1lbXB0eSI+xJBhbmcgdOG6o2kgZGFuaCBzw6Fj",
  "aCBnYW1lLi4uPC9kaXY+JzsKICB0cnl7CiAgICBjb25zdCByZXMgPSBhd2FpdCBmZXRjaChBUElf",
  "QkFTRSArICcvYXBpL2dldGtleS9nYW1lcycsIHsgY2FjaGU6J25vLXN0b3JlJyB9KTsKICAgIGdr",
  "R2FtZXMgPSBhd2FpdCByZXMuanNvbigpOwogIH1jYXRjaChlKXsKICAgIGdrR2FtZXMgPSBbXTsK",
  "ICB9CiAgcmVuZGVyR2tHYW1lR3JpZCgpOwogIHJlbmRlckdrR2FtZUdyaWRIb21lKCk7IC8vIMSR",
  "4buTbmcgYuG7mSBsdcO0biBncmlkIHRyw6puIHRyYW5nIGNo4bunIHbhu5tpIGPDuW5nIGThu68g",
  "bGnhu4d1IHbhu6thIHThuqNpCn0KJCgnYnRuQ2xvc2VHa0Nob29zZUdhbWUnKS5hZGRFdmVudExp",
  "c3RlbmVyKCdjbGljaycsICgpPT4gJCgnZ2tDaG9vc2VHYW1lTW9kYWxCZycpLmNsYXNzTGlzdC5y",
  "ZW1vdmUoJ3Nob3cnKSk7CgpmdW5jdGlvbiByZW5kZXJHa0dhbWVHcmlkKCl7CiAgY29uc3QgZ3Jp",
  "ZCA9ICQoJ2drR2FtZUdyaWQnKTsKICBjb25zdCBlbXB0eSA9ICQoJ2drR2FtZUVtcHR5U3RhdGUn",
  "KTsKICBncmlkLmlubmVySFRNTCA9ICcnOwogIGVtcHR5LnN0eWxlLmRpc3BsYXkgPSBna0dhbWVz",
  "Lmxlbmd0aCA/ICdub25lJyA6ICdibG9jayc7CiAgZ2tHYW1lcy5mb3JFYWNoKGc9PnsKICAgIGNv",
  "bnN0IGNhcmQgPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCdkaXYnKTsKICAgIGNhcmQuY2xhc3NO",
  "YW1lID0gJ2drLWdhbWUtY2FyZCc7CiAgICBjYXJkLmRhdGFzZXQuaWQgPSBnLmlkOwogICAgY2Fy",
  "ZC5pbm5lckhUTUwgPSBgCiAgICAgIDxkaXYgY2xhc3M9ImxvZ28iPiR7Zy5sb2dvID8gYDxpbWcg",
  "c3JjPSIke2cubG9nb30iPmAgOiAn8J+Orid9PC9kaXY+CiAgICAgIDxkaXYgY2xhc3M9Im5hbWUi",
  "PiR7Zy5uYW1lfTwvZGl2PgogICAgYDsKICAgIGNhcmQuYWRkRXZlbnRMaXN0ZW5lcignY2xpY2sn",
  "LCAoKT0+IG9wZW5Ha0Nob29zZUR1cmF0aW9uTW9kYWwoZykpOwogICAgZ3JpZC5hcHBlbmRDaGls",
  "ZChjYXJkKTsKICB9KTsKfQoKLyogLS0tLS0tLS0tLSBHcmlkIEdldEtleSBOR0FZIFRSw4pOIFRS",
  "QU5HIENI4bumIChjw7luZyBraeG7g3UgY2FyZCB24bubaSBOaMOzbSBz4bqjbiBwaOG6qW0pIC0t",
  "LS0tLS0tLS0KICAgRMO5bmcgY2h1bmcgZOG7ryBsaeG7h3UgZ2tHYW1lcyDEkcOjIHThuqNpIHF1",
  "YSBvcGVuR2tDaG9vc2VHYW1lTW9kYWwvbG9hZEdrR2FtZXNIb21lOyBraGkgYuG6pW0gIk11YSBL",
  "ZXkiCiAgIG3hu58gdGjhurNuZyBtb2RhbCBjaOG7jW4gZ8OzaSBI4buiUCBOSOG6pFQgKGtow7Ru",
  "ZyBxdWEgbW9kYWwgY2jhu41uLWdhbWUvY2jhu41uLXRo4budaS1o4bqhbiBraeG7g3UgY8WpKS4g",
  "LS0tLS0tLS0tLSAqLwphc3luYyBmdW5jdGlvbiBsb2FkR2tHYW1lc0hvbWUoKXsKICB0cnl7CiAg",
  "ICBjb25zdCByZXMgPSBhd2FpdCBmZXRjaChBUElfQkFTRSArICcvYXBpL2dldGtleS9nYW1lcycs",
  "IHsgY2FjaGU6J25vLXN0b3JlJyB9KTsKICAgIGdrR2FtZXMgPSBhd2FpdCByZXMuanNvbigpOwog",
  "IH1jYXRjaChlKXsKICAgIGNvbnNvbGUud2FybignW0tleVZhdWx0IFN0b3JlXSBLaMO0bmcgdOG6",
  "o2kgxJHGsOG7o2MgZGFuaCBzw6FjaCBnYW1lIEdldEtleScsIGUpOwogICAgZ2tHYW1lcyA9IFtd",
  "OwogIH0KICByZW5kZXJHa0dhbWVHcmlkSG9tZSgpOwp9CgpmdW5jdGlvbiByZW5kZXJHa0dhbWVH",
  "cmlkSG9tZSgpewogIGNvbnN0IGdyaWQgPSAkKCdna0dhbWVHcmlkSG9tZScpOwogIGNvbnN0IGVt",
  "cHR5ID0gJCgnZ2tHYW1lRW1wdHlTdGF0ZUhvbWUnKTsKICBjb25zdCBjb3VudExhYmVsID0gJCgn",
  "Z2tHYW1lQ291bnRMYWJlbCcpOwogIGlmKCFncmlkKSByZXR1cm47CiAgZ3JpZC5pbm5lckhUTUwg",
  "PSAnJzsKICBlbXB0eS5zdHlsZS5kaXNwbGF5ID0gZ2tHYW1lcy5sZW5ndGggPyAnbm9uZScgOiAn",
  "YmxvY2snOwogIGNvdW50TGFiZWwudGV4dENvbnRlbnQgPSBna0dhbWVzLmxlbmd0aCArICcgZ2Ft",
  "ZSc7CiAgZ2tHYW1lcy5mb3JFYWNoKGc9PnsKICAgIGNvbnN0IHRvdGFsUm91bmRzID0gKGcuZHVy",
  "YXRpb25zfHxbXSkucmVkdWNlKChzdW0sZCk9PiBzdW0gKyAoZC5yb3VuZHN8fDApLCAwKTsKICAg",
  "IGNvbnN0IGNhcmQgPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCdkaXYnKTsKICAgIGNhcmQuY2xh",
  "c3NOYW1lID0gJ2NhcmQnOwogICAgY2FyZC5pbm5lckhUTUwgPSBgCiAgICAgIDxkaXYgY2xhc3M9",
  "ImxvZ28iPiR7Zy5sb2dvID8gYDxpbWcgc3JjPSIke2cubG9nb30iPmAgOiAn8J+Orid9PC9kaXY+",
  "CiAgICAgIDxoMz4ke2cubmFtZX08L2gzPgogICAgICA8ZGl2IGNsYXNzPSJtZXRhIj4KICAgICAg",
  "ICA8c3Bhbj4keyhnLmR1cmF0aW9uc3x8W10pLmxlbmd0aH0gbG/huqFpIGtleSDCtyB2xrDhu6N0",
  "IGxpbmsgbmjhuq1uIG1p4buFbiBwaMOtPC9zcGFuPgogICAgICAgIDxzcGFuIGNsYXNzPSJzdG9j",
  "ayAke2cuc3RvY2s+MCA/ICdpbicgOiAnb3V0J30iPiR7Zy5zdG9jaz4wID8gJ+KclCBDw7JuIGjD",
  "oG5nJyA6ICfinJYgSOG6v3QgaMOgbmcnfTwvc3Bhbj4KICAgICAgPC9kaXY+CiAgICAgIDxidXR0",
  "b24gY2xhc3M9ImJ0biBidXktYnRuIiBkYXRhLWdpZD0iJHtnLmlkfSI+TXVhIEtleTwvYnV0dG9u",
  "PgogICAgYDsKICAgIGdyaWQuYXBwZW5kQ2hpbGQoY2FyZCk7CiAgfSk7Cn0KCiQoJ2drR2FtZUdy",
  "aWRIb21lJykuYWRkRXZlbnRMaXN0ZW5lcignY2xpY2snLCAoZSk9PnsKICBjb25zdCBidG4gPSBl",
  "LnRhcmdldC5jbG9zZXN0KCcuYnV5LWJ0bicpOwogIGlmKCFidG4pIHJldHVybjsKICBjb25zdCBn",
  "YW1lID0gZ2tHYW1lcy5maW5kKGc9PmcuaWQ9PT1idG4uZGF0YXNldC5naWQpOwogIGlmKCFnYW1l",
  "KXsgc2hvd1RvYXN0KCdHYW1lIGtow7RuZyBjw7JuIHThu5NuIHThuqFpLCB2dWkgbMOybmcgdOG6",
  "o2kgbOG6oWkgdHJhbmcnKTsgcmV0dXJuOyB9CiAgb3BlbkdrVW5pZmllZER1cmF0aW9uTW9kYWwo",
  "Z2FtZSk7Cn0pOwoKLyogTeG7nyBtb2RhbCBjaOG7jW4gZ8OzaSBI4buiUCBOSOG6pFQgY2hvIEdl",
  "dEtleSAoY2jhu41uIHRo4budaSBo4bqhbiBy4buTaSBi4bqvdCDEkeG6p3Ugdsaw4bujdCBsaW5r",
  "LCBraMO0bmcgbeG6pXQgdGnhu4FuKS4gKi8KZnVuY3Rpb24gb3BlbkdrVW5pZmllZER1cmF0aW9u",
  "TW9kYWwoZ2FtZSl7CiAgZ2tTZWxlY3RlZEdhbWUgPSBnYW1lOwogIGdrU2VsZWN0ZWREdXJhdGlv",
  "biA9IG51bGw7CiAgb3BlblVuaWZpZWRQbGFuTW9kYWwoewogICAgbW9kZTogJ2dldGtleScsCiAg",
  "ICBsb2dvOiBnYW1lLmxvZ28sCiAgICB0aXRsZTogZ2FtZS5uYW1lLAogICAgc3VidGl0bGU6ICdD",
  "aOG7jW4gbG/huqFpIGtleSBi4bqhbiBtdeG7kW4gbmjhuq1uLiBUaOG7nWkgaOG6oW4gY8Ogbmcg",
  "ZMOgaSwgc+G7kSBsxrDhu6N0IHbGsOG7o3QgbGluayBjw6BuZyBuaGnhu4F1LicsCiAgICBvcHRp",
  "b25zOiAoZ2FtZS5kdXJhdGlvbnN8fFtdKS5tYXAoZD0+KHsKICAgICAgaWQ6IGQuaWQsCiAgICAg",
  "IGljb246ICfwn5SRJywKICAgICAgbGFiZWw6IGZtdEdrRHVyYXRpb25QdWJsaWMoZCksCiAgICAg",
  "IHN1YjogZC5yb3VuZHMgKyAnIGzGsOG7o3Qgdsaw4bujdCBsaW5rJywKICAgICAgcHJpY2U6IG51",
  "bGwsCiAgICAgIHN0b2NrTGFiZWw6IGdhbWUuc3RvY2s+MCA/ICdNaeG7hW4gcGjDrScgOiAnJywK",
  "ICAgICAgaW5TdG9jazogZ2FtZS5zdG9jayA+IDAsCiAgICAgIHRhZzogbnVsbAogICAgfSkpLAog",
  "ICAgb25TZWxlY3Q6IChkdXJhdGlvbklkKT0+ewogICAgICBna1NlbGVjdGVkRHVyYXRpb24gPSAo",
  "Z2FtZS5kdXJhdGlvbnN8fFtdKS5maW5kKGQ9PmQuaWQ9PT1kdXJhdGlvbklkKTsKICAgICAgY2xv",
  "c2VVbmlmaWVkUGxhbk1vZGFsKCk7CiAgICAgIHN0YXJ0R2tGbG93VW5pZmllZCgpOwogICAgfQog",
  "IH0pOwp9CgovKiBC4bqvdCDEkeG6p3UgcGhpw6puIHbGsOG7o3QgbGluayDigJQgdMawxqFuZyDE",
  "kcawxqFuZyBow6BuaCB2aSBj4bunYSBuw7p0IGJ0blN0YXJ0R2tGbG93IGPFqSBuaMawbmcga2jh",
  "u59pIMSR4buZbmcKICAgdOG7qyBtb2RhbCBo4bujcCBuaOG6pXQgbeG7m2kgdGhheSB2w6wgbW9k",
  "YWwgZ2tDaG9vc2VEdXJhdGlvbk1vZGFsQmcgY8WpLiAqLwphc3luYyBmdW5jdGlvbiBzdGFydEdr",
  "Rmxvd1VuaWZpZWQoKXsKICBpZighZ2tTZWxlY3RlZER1cmF0aW9uIHx8ICFna1NlbGVjdGVkR2Ft",
  "ZSkgcmV0dXJuOwogIHRyeXsKICAgIGNvbnN0IHJlcyA9IGF3YWl0IGZldGNoKEFQSV9CQVNFICsg",
  "Jy9hcGkvZ2V0a2V5L3N0YXJ0JywgewogICAgICBtZXRob2Q6J1BPU1QnLCBoZWFkZXJzOnsnQ29u",
  "dGVudC1UeXBlJzonYXBwbGljYXRpb24vanNvbid9LAogICAgICBib2R5OiBKU09OLnN0cmluZ2lm",
  "eSh7IGdhbWVJZDogZ2tTZWxlY3RlZEdhbWUuaWQsIGR1cmF0aW9uSWQ6IGdrU2VsZWN0ZWREdXJh",
  "dGlvbi5pZCB9KQogICAgfSk7CiAgICBjb25zdCBkYXRhID0gYXdhaXQgcmVzLmpzb24oKTsKICAg",
  "IGlmKCFyZXMub2sgfHwgIWRhdGEub2spewogICAgICBjb25zdCBtYXAgPSB7IGdhbWVfbm90X2Zv",
  "dW5kOidHYW1lIGtow7RuZyB04buTbiB04bqhaScsIGR1cmF0aW9uX25vdF9mb3VuZDonTG/huqFp",
  "IGtleSBraMO0bmcgdOG7k24gdOG6oWknLCBvdXRfb2Zfc3RvY2s6J0dhbWUgbsOgeSDEkcOjIGjh",
  "ur90IGtleScgfTsKICAgICAgdGhyb3cgbmV3IEVycm9yKG1hcFtkYXRhLmVycm9yXSB8fCAnS2jD",
  "tG5nIHRo4buDIGLhuq90IMSR4bqndSwgdnVpIGzDsm5nIHRo4butIGzhuqFpJyk7CiAgICB9CiAg",
  "ICBna1Nlc3Npb25JZCA9IGRhdGEuc2Vzc2lvbklkOwogICAgZ2tUb3RhbFJvdW5kcyA9IGRhdGEu",
  "dG90YWxSb3VuZHM7CiAgICBna0N1cnJlbnRSb3VuZCA9IGRhdGEuY3VycmVudFJvdW5kOwogICAg",
  "b3BlbkdrRmxvd01vZGFsKGRhdGEubGluayk7CiAgfWNhdGNoKGUpewogICAgc2hvd1RvYXN0KGUu",
  "bWVzc2FnZSk7CiAgfQp9Cgpsb2FkR2tHYW1lc0hvbWUoKTsKCmZ1bmN0aW9uIGZtdEdrRHVyYXRp",
  "b25QdWJsaWMoZCl7CiAgY29uc3QgdW5pdExhYmVsID0gZC51bml0PT09J2hvdXInID8gJ2dp4bud",
  "JyA6IGQudW5pdD09PSdtb250aCcgPyAndGjDoW5nJyA6ICduZ8OgeSc7CiAgcmV0dXJuIGQubGFi",
  "ZWwgfHwgKGQuYW1vdW50ICsgJyAnICsgdW5pdExhYmVsKTsKfQoKZnVuY3Rpb24gb3BlbkdrQ2hv",
  "b3NlRHVyYXRpb25Nb2RhbChnYW1lKXsKICBna1NlbGVjdGVkR2FtZSA9IGdhbWU7CiAgZ2tTZWxl",
  "Y3RlZER1cmF0aW9uID0gbnVsbDsKICAkKCdna0Nob29zZUdhbWVNb2RhbEJnJykuY2xhc3NMaXN0",
  "LnJlbW92ZSgnc2hvdycpOwogICQoJ2drRHVyYXRpb25HYW1lTmFtZScpLnRleHRDb250ZW50ID0g",
  "Z2FtZS5uYW1lOwogICQoJ2drRHVyYXRpb25FcnJvcicpLmNsYXNzTGlzdC5yZW1vdmUoJ3Nob3cn",
  "KTsKICBjb25zdCBsaXN0ID0gJCgnZ2tEdXJhdGlvbkxpc3RQdWJsaWMnKTsKICBsaXN0LmlubmVy",
  "SFRNTCA9ICcnOwogIChnYW1lLmR1cmF0aW9ucyB8fCBbXSkuZm9yRWFjaChkPT57CiAgICBjb25z",
  "dCBpdGVtID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgnZGl2Jyk7CiAgICBpdGVtLmNsYXNzTmFt",
  "ZSA9ICdnay1kdXJhdGlvbi1pdGVtJzsKICAgIGl0ZW0uZGF0YXNldC5pZCA9IGQuaWQ7CiAgICBp",
  "dGVtLmlubmVySFRNTCA9IGAKICAgICAgPGRpdj48ZGl2IGNsYXNzPSJsYmwiPiR7Zm10R2tEdXJh",
  "dGlvblB1YmxpYyhkKX08L2Rpdj48ZGl2IGNsYXNzPSJyb3VuZHMiPiR7ZC5yb3VuZHN9IGzGsOG7",
  "o3Qgdsaw4bujdCBsaW5rPC9kaXY+PC9kaXY+CiAgICAgIDxkaXY+JHtnYW1lLnN0b2NrPjAgPyAn",
  "4pyUJyA6ICfinJYgSOG6v3QgaMOgbmcnfTwvZGl2PgogICAgYDsKICAgIGl0ZW0uYWRkRXZlbnRM",
  "aXN0ZW5lcignY2xpY2snLCAoKT0+ewogICAgICBkb2N1bWVudC5xdWVyeVNlbGVjdG9yQWxsKCcu",
  "Z2stZHVyYXRpb24taXRlbScpLmZvckVhY2goZWw9PmVsLmNsYXNzTGlzdC5yZW1vdmUoJ3NlbGVj",
  "dGVkJykpOwogICAgICBpdGVtLmNsYXNzTGlzdC5hZGQoJ3NlbGVjdGVkJyk7CiAgICAgIGdrU2Vs",
  "ZWN0ZWREdXJhdGlvbiA9IGQ7CiAgICB9KTsKICAgIGxpc3QuYXBwZW5kQ2hpbGQoaXRlbSk7CiAg",
  "fSk7CiAgJCgnZ2tDaG9vc2VEdXJhdGlvbk1vZGFsQmcnKS5jbGFzc0xpc3QuYWRkKCdzaG93Jyk7",
  "Cn0KJCgnYnRuQmFja0drRHVyYXRpb24nKS5hZGRFdmVudExpc3RlbmVyKCdjbGljaycsICgpPT57",
  "CiAgJCgnZ2tDaG9vc2VEdXJhdGlvbk1vZGFsQmcnKS5jbGFzc0xpc3QucmVtb3ZlKCdzaG93Jyk7",
  "CiAgb3BlbkdrQ2hvb3NlR2FtZU1vZGFsKCk7Cn0pOwoKJCgnYnRuU3RhcnRHa0Zsb3cnKS5hZGRF",
  "dmVudExpc3RlbmVyKCdjbGljaycsIGFzeW5jICgpPT57CiAgY29uc3QgZXJyQm94ID0gJCgnZ2tE",
  "dXJhdGlvbkVycm9yJyk7CiAgZXJyQm94LmNsYXNzTGlzdC5yZW1vdmUoJ3Nob3cnKTsKICBpZigh",
  "Z2tTZWxlY3RlZER1cmF0aW9uKXsgZXJyQm94LnRleHRDb250ZW50ID0gJ1Z1aSBsw7JuZyBjaOG7",
  "jW4gMSBsb+G6oWkga2V5JzsgZXJyQm94LmNsYXNzTGlzdC5hZGQoJ3Nob3cnKTsgcmV0dXJuOyB9",
  "CiAgaWYoKGdrU2VsZWN0ZWRHYW1lLnN0b2NrfHwwKSA8PSAwKXsgZXJyQm94LnRleHRDb250ZW50",
  "ID0gJ0dhbWUgbsOgeSBoaeG7h24gxJHDoyBo4bq/dCBrZXksIHZ1aSBsw7JuZyB0aOG7rSBs4bqh",
  "aSBzYXUnOyBlcnJCb3guY2xhc3NMaXN0LmFkZCgnc2hvdycpOyByZXR1cm47IH0KCiAgdHJ5ewog",
  "ICAgY29uc3QgcmVzID0gYXdhaXQgZmV0Y2goQVBJX0JBU0UgKyAnL2FwaS9nZXRrZXkvc3RhcnQn",
  "LCB7CiAgICAgIG1ldGhvZDonUE9TVCcsIGhlYWRlcnM6eydDb250ZW50LVR5cGUnOidhcHBsaWNh",
  "dGlvbi9qc29uJ30sCiAgICAgIGJvZHk6IEpTT04uc3RyaW5naWZ5KHsgZ2FtZUlkOiBna1NlbGVj",
  "dGVkR2FtZS5pZCwgZHVyYXRpb25JZDogZ2tTZWxlY3RlZER1cmF0aW9uLmlkIH0pCiAgICB9KTsK",
  "ICAgIGNvbnN0IGRhdGEgPSBhd2FpdCByZXMuanNvbigpOwogICAgaWYoIXJlcy5vayB8fCAhZGF0",
  "YS5vayl7CiAgICAgIGNvbnN0IG1hcCA9IHsgZ2FtZV9ub3RfZm91bmQ6J0dhbWUga2jDtG5nIHTh",
  "u5NuIHThuqFpJywgZHVyYXRpb25fbm90X2ZvdW5kOidMb+G6oWkga2V5IGtow7RuZyB04buTbiB0",
  "4bqhaScsIG91dF9vZl9zdG9jazonR2FtZSBuw6B5IMSRw6MgaOG6v3Qga2V5JyB9OwogICAgICB0",
  "aHJvdyBuZXcgRXJyb3IobWFwW2RhdGEuZXJyb3JdIHx8ICdLaMO0bmcgdGjhu4MgYuG6r3QgxJHh",
  "uqd1LCB2dWkgbMOybmcgdGjhu60gbOG6oWknKTsKICAgIH0KICAgIGdrU2Vzc2lvbklkID0gZGF0",
  "YS5zZXNzaW9uSWQ7CiAgICBna1RvdGFsUm91bmRzID0gZGF0YS50b3RhbFJvdW5kczsKICAgIGdr",
  "Q3VycmVudFJvdW5kID0gZGF0YS5jdXJyZW50Um91bmQ7CiAgICAkKCdna0Nob29zZUR1cmF0aW9u",
  "TW9kYWxCZycpLmNsYXNzTGlzdC5yZW1vdmUoJ3Nob3cnKTsKICAgIG9wZW5Ha0Zsb3dNb2RhbChk",
  "YXRhLmxpbmspOwogIH1jYXRjaChlKXsKICAgIGVyckJveC50ZXh0Q29udGVudCA9IGUubWVzc2Fn",
  "ZTsKICAgIGVyckJveC5jbGFzc0xpc3QuYWRkKCdzaG93Jyk7CiAgfQp9KTsKCmZ1bmN0aW9uIHJl",
  "bmRlckdrUHJvZ3Jlc3MoKXsKICBjb25zdCB3cmFwID0gJCgnZ2tQcm9ncmVzc0RvdHMnKTsKICB3",
  "cmFwLmlubmVySFRNTCA9ICcnOwogIGZvcihsZXQgaT0xO2k8PWdrVG90YWxSb3VuZHM7aSsrKXsK",
  "ICAgIGNvbnN0IGRvdCA9IGRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoJ2RpdicpOwogICAgZG90LmNs",
  "YXNzTmFtZSA9ICdkb3QnICsgKGkgPCBna0N1cnJlbnRSb3VuZCA/ICcgZG9uZScgOiBpID09PSBn",
  "a0N1cnJlbnRSb3VuZCA/ICcgY3VycmVudCcgOiAnJyk7CiAgICB3cmFwLmFwcGVuZENoaWxkKGRv",
  "dCk7CiAgfQp9CgpmdW5jdGlvbiBvcGVuR2tGbG93TW9kYWwobGluayl7CiAgJCgnZ2tGbG93R2Ft",
  "ZUxhYmVsJykudGV4dENvbnRlbnQgPSBna1NlbGVjdGVkR2FtZS5uYW1lICsgJyDCtyAnICsgZm10",
  "R2tEdXJhdGlvblB1YmxpYyhna1NlbGVjdGVkRHVyYXRpb24pOwogICQoJ2drUm91bmRMYWJlbCcp",
  "LnRleHRDb250ZW50ID0gYEzGsOG7o3QgJHtna0N1cnJlbnRSb3VuZH0vJHtna1RvdGFsUm91bmRz",
  "fWA7CiAgJCgnYnRuT3BlbkdrTGluaycpLmhyZWYgPSBsaW5rOwogICQoJ2J0bk9wZW5Ha0xpbmsn",
  "KS50ZXh0Q29udGVudCA9IGBN4bufIGzhuqFpIGxpbmsgdsaw4bujdCAobMaw4bujdCAke2drQ3Vy",
  "cmVudFJvdW5kfS8ke2drVG90YWxSb3VuZHN9KWA7CiAgJCgnZ2tGbG93RXJyb3InKS5jbGFzc0xp",
  "c3QucmVtb3ZlKCdzaG93Jyk7CiAgcmVuZGVyR2tQcm9ncmVzcygpOwogICQoJ2drRmxvd01vZGFs",
  "QmcnKS5jbGFzc0xpc3QuYWRkKCdzaG93Jyk7CiAgLy8gVOG7sSDEkeG7mW5nIG3hu58gbGluayB2",
  "xrDhu6N0IG5nYXkga2hpIGLGsOG7m2MgdsOgbyBsxrDhu6N0IG7DoHkg4oCUIGtow6FjaCBLSMOU",
  "TkcgY+G6p24gYuG6pW0gdGjDqm0gbsO6dCBuw6BvIMSR4buDICJt4bufIiBsaW5rLgogIC8vIE7h",
  "ur91IHRyw6xuaCBkdXnhu4d0IGNo4bq3biBwb3B1cCwgbsO6dCAiTeG7nyBs4bqhaSBsaW5rIHbG",
  "sOG7o3QiIHBow61hIHRyw6puIHbhuqtuIGNobyBraMOhY2ggdOG7sSBt4bufIHRo4bunIGPDtG5n",
  "LgogIGNvbnN0IG9wZW5lZCA9IHdpbmRvdy5vcGVuKGxpbmssICdfYmxhbmsnLCAnbm9vcGVuZXIn",
  "KTsKICBpZighb3BlbmVkKXsKICAgIHNob3dUb2FzdCgnVHLDrG5oIGR1eeG7h3QgxJHDoyBjaOG6",
  "t24gbeG7nyBsaW5rIHThu7EgxJHhu5luZyDigJQgdnVpIGzDsm5nIGLhuqVtIG7DunQgIk3hu58g",
  "bOG6oWkgbGluayB2xrDhu6N0IiBiw6puIGTGsOG7m2knKTsKICB9Cn0KJCgnYnRuQ2xvc2VHa0Zs",
  "b3cnKS5hZGRFdmVudExpc3RlbmVyKCdjbGljaycsICgpPT4gJCgnZ2tGbG93TW9kYWxCZycpLmNs",
  "YXNzTGlzdC5yZW1vdmUoJ3Nob3cnKSk7CgokKCdidG5Db25maXJtR2tTdGVwJykuYWRkRXZlbnRM",
  "aXN0ZW5lcignY2xpY2snLCBhc3luYyAoKT0+ewogIGNvbnN0IGVyckJveCA9ICQoJ2drRmxvd0Vy",
  "cm9yJyk7CiAgZXJyQm94LmNsYXNzTGlzdC5yZW1vdmUoJ3Nob3cnKTsKICBjb25zdCBidG4gPSAk",
  "KCdidG5Db25maXJtR2tTdGVwJyk7CiAgYnRuLmRpc2FibGVkID0gdHJ1ZTsgYnRuLnRleHRDb250",
  "ZW50ID0gJ8SQYW5nIGtp4buDbSB0cmEuLi4nOwogIHRyeXsKICAgIGNvbnN0IHJlcyA9IGF3YWl0",
  "IGZldGNoKEFQSV9CQVNFICsgJy9hcGkvZ2V0a2V5L25leHQnLCB7CiAgICAgIG1ldGhvZDonUE9T",
  "VCcsIGhlYWRlcnM6eydDb250ZW50LVR5cGUnOidhcHBsaWNhdGlvbi9qc29uJ30sCiAgICAgIGJv",
  "ZHk6IEpTT04uc3RyaW5naWZ5KHsgc2Vzc2lvbklkOiBna1Nlc3Npb25JZCB9KQogICAgfSk7CiAg",
  "ICBjb25zdCBkYXRhID0gYXdhaXQgcmVzLmpzb24oKTsKICAgIGlmKCFyZXMub2sgfHwgIWRhdGEu",
  "b2spewogICAgICBjb25zdCBtYXAgPSB7CiAgICAgICAgc2Vzc2lvbl9ub3RfZm91bmQ6J1BoacOq",
  "biDEkcOjIGjhur90IGjhuqFuLCB2dWkgbMOybmcgYuG6r3QgxJHhuqd1IGzhuqFpJywKICAgICAg",
  "ICBnYW1lX25vdF9mb3VuZDonR2FtZSBraMO0bmcgdOG7k24gdOG6oWknLAogICAgICAgIG91dF9v",
  "Zl9zdG9jazonxJDDoyBo4bq/dCBrZXksIHZ1aSBsw7JuZyB0aOG7rSBs4bqhaSBzYXUnLAogICAg",
  "ICAgIG5vdF9jb25maXJtZWRfeWV0OidC4bqhbiBDSMavQSB2xrDhu6N0IGxpbmsg4bufIGzGsOG7",
  "o3QgbsOgeSDigJQgdnVpIGzDsm5nIG3hu58gbGluayB2w6AgaG/DoG4gdGjDoG5oIHRyYW5nIMSR",
  "w61jaCB0csaw4bubYyBraGkgYuG6pW0gIlTDtGkgxJHDoyB2xrDhu6N0IGxpbmsiJwogICAgICB9",
  "OwogICAgICB0aHJvdyBuZXcgRXJyb3IobWFwW2RhdGEuZXJyb3JdIHx8ICdDw7MgbOG7l2kgeOG6",
  "o3kgcmEsIHZ1aSBsw7JuZyB0aOG7rSBs4bqhaScpOwogICAgfQogICAgaWYoZGF0YS5kb25lKXsK",
  "ICAgICAgJCgnZ2tGbG93TW9kYWxCZycpLmNsYXNzTGlzdC5yZW1vdmUoJ3Nob3cnKTsKICAgICAg",
  "JCgnZ2tSZXN1bHRLZXlWYWx1ZScpLnRleHRDb250ZW50ID0gZGF0YS5rZXk7CiAgICAgICQoJ2dr",
  "UmVzdWx0TW9kYWxCZycpLmNsYXNzTGlzdC5hZGQoJ3Nob3cnKTsKICAgIH0gZWxzZSB7CiAgICAg",
  "IGdrQ3VycmVudFJvdW5kID0gZGF0YS5jdXJyZW50Um91bmQ7CiAgICAgIG9wZW5Ha0Zsb3dNb2Rh",
  "bChkYXRhLmxpbmspOwogICAgfQogIH1jYXRjaChlKXsKICAgIGVyckJveC50ZXh0Q29udGVudCA9",
  "IGUubWVzc2FnZTsKICAgIGVyckJveC5jbGFzc0xpc3QuYWRkKCdzaG93Jyk7CiAgfWZpbmFsbHl7",
  "CiAgICBidG4uZGlzYWJsZWQgPSBmYWxzZTsgYnRuLnRleHRDb250ZW50ID0gJ1TDtGkgxJHDoyB2",
  "xrDhu6N0IGxpbmsnOwogIH0KfSk7CgokKCdidG5DbG9zZUdrUmVzdWx0JykuYWRkRXZlbnRMaXN0",
  "ZW5lcignY2xpY2snLCAoKT0+ICQoJ2drUmVzdWx0TW9kYWxCZycpLmNsYXNzTGlzdC5yZW1vdmUo",
  "J3Nob3cnKSk7CiQoJ2J0bkNvcHlHa1Jlc3VsdEtleScpLmFkZEV2ZW50TGlzdGVuZXIoJ2NsaWNr",
  "JywgKCk9PnsKICBjb25zdCB2YWwgPSAkKCdna1Jlc3VsdEtleVZhbHVlJykudGV4dENvbnRlbnQ7",
  "CiAgbmF2aWdhdG9yLmNsaXBib2FyZC53cml0ZVRleHQodmFsKS50aGVuKCgpPT4gc2hvd1RvYXN0",
  "KCfEkMOjIHNhbyBjaMOpcCBrZXknKSkuY2F0Y2goKCk9PiBzaG93VG9hc3QoJ0tow7RuZyBzYW8g",
  "Y2jDqXAgxJHGsOG7o2MsIHZ1aSBsw7JuZyBjb3B5IHRo4bunIGPDtG5nJykpOwp9KTsKCi8qIC0t",
  "LS0tLS0tLS0gS2jhu59pIMSR4buZbmcgJiB04buxIGzDoG0gbeG7m2kgc+G6o24gcGjhuqltIHRo",
  "ZW8gYWRtaW4gLS0tLS0tLS0tLSAqLwpsb2FkUHJvZHVjdHMoKTsKc2V0SW50ZXJ2YWwobG9hZFBy",
  "b2R1Y3RzLCA4MDAwKTsgLy8gdOG7sSDEkeG7mW5nIGPhuq1wIG5o4bqtdCBz4bqjbiBwaOG6qW0v",
  "dOG7k24ga2hvIHRoZW8gYWRtaW4gZ+G6p24gbmjGsCByZWFsLXRpbWUKPC9zY3JpcHQ+CjwvYm9k",
  "eT4KPC9odG1sPgoK",
];
const STORE_PAGE = Buffer.from(STORE_B64_CHUNKS.join(''), 'base64').toString('utf8');

const HTML_PAGE = HTML_LINES.join(String.fromCharCode(10));

/* ---------------- Lưu trữ dữ liệu ra file (persist thật trên server) ---------------- */
function defaultState(){
  return {
    adminPassword: '120510@',
    loginHistory: [],
    keysStore: {},
    sellers: [],
    blockedIPs: [],
    scanState: {},
    lastScanTime: null,
    statsHidden: false,
    apiApps: [],     // { id, appId, status: 'pending'|'allowed'|'denied', createdAt, lastUsedAt, totalChecks }
    verifyLogs: [],   // { time, appId, key, valid, reason }
    products: [],     // { id, name, logo, keyPrefix, price, maxDevices, durationAmount, durationUnit, active, createdAt }
    discountCodes: [],// { id, code, percent, maxUses, usedCount, expiresAt, active, createdAt }
    customers: [],    // { id, username, passwordHash, createdAt, balance, role: 'customer'|'admin', topupHistory:[], transactionHistory:[] }
    customerSessions: {}, // { token: { customerId, username, createdAt } }
    /* Thông tin tài khoản ngân hàng dùng để sinh QR động (VietQR) cho nạp tiền tự động.
       Admin có thể đổi qua "/api/state" (POST) như các trường cấu hình khác. */
    bankInfo: {
      bankId: 'MB',              // mã ngân hàng dùng cho VietQR (MB = MBBank)
      accountNo: '0364837118',
      accountName: 'LUONG VAN TUYEN'
    },
    /* Cấu hình đối soát tự động qua SePay (my.sepay.vn): mỗi khi có tiền vào tài khoản
       MB Bank ở trên, SePay gọi webhook /api/sepay-webhook kèm nội dung CK + số tiền.
       apiKey dùng để xác thực request webhook đến thực sự từ SePay (đặt cùng giá trị
       với "API Key" cấu hình bên trong webhook của SePay — Authorization: Apikey <giá trị>).
       Admin có thể đổi qua "/api/state" như các trường cấu hình khác. */
    sepayConfig: {
      enabled: false,   // bật/tắt đối soát tự động; false = chỉ dùng duyệt tay như trước
      apiKey: ''        // API Key bí mật để xác thực webhook từ SePay
    },
    topupRequests: [], // { id, customerId, username, amount, method, status:'pending'|'approved'|'rejected'|'expired', createdAt, expiresAt, note, matchedTransaction }
    getKeyGames: [],    // { id, name, logo, keyPrefix, active, createdAt, durations: [{ id, label, unit, amount, rounds }] }
    getKeySessions: {}  // { sessionId: { gameId, durationId, rounds, currentRound, done, key, createdAt, ip } }
  };
}

let db = loadDB();
let saveTimer = null;

function loadDB(){
  try{
    const raw = fs.readFileSync(DB_FILE, 'utf8');
    const parsed = JSON.parse(raw);
    return { ...defaultState(), ...parsed };
  }catch(e){
    /* Nếu db.json bị hỏng (JSON không hợp lệ) hoặc chưa tồn tại, thay vì để lỗi
       lan ra ngoài làm sập tiến trình, ta sao lưu file lỗi (nếu có) rồi khởi
       tạo lại dữ liệu mặc định, giúp server luôn khởi động thành công. */
    try{
      if(fs.existsSync(DB_FILE)){
        fs.copyFileSync(DB_FILE, DB_FILE + '.broken-' + Date.now() + '.bak');
        console.error('[KeyVault] db.json bị lỗi/hỏng, đã sao lưu và tạo dữ liệu mặc định:', e.message);
      }
    }catch(backupErr){ /* bỏ qua lỗi sao lưu, không ảnh hưởng khởi động */ }
    return defaultState();
  }
}

function saveDBNow(){
  try{
    fs.writeFileSync(DB_FILE, JSON.stringify(db, null, 2), 'utf8');
  }catch(e){
    console.error('[KeyVault] Lỗi ghi db.json:', e.message);
  }
}

// Gộp nhiều lần ghi liên tiếp lại để tránh ghi đĩa quá nhiều lần/giây
function saveDBDebounced(){
  clearTimeout(saveTimer);
  saveTimer = setTimeout(saveDBNow, 150);
}

/* ---------------- Tiện ích HTTP ---------------- */
function sendJSON(res, status, obj){
  const body = JSON.stringify(obj);
  res.writeHead(status, {
    'Content-Type': 'application/json; charset=utf-8',
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'GET,POST,DELETE,OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type'
  });
  res.end(body);
}

function readJSONBody(req){
  return new Promise((resolve, reject)=>{
    let data = '';
    req.on('data', chunk=>{
      data += chunk;
      if(data.length > 10 * 1024 * 1024){ reject(new Error('payload_too_large')); req.destroy(); }
    });
    req.on('end', ()=>{
      if(!data){ resolve({}); return; }
      try{ resolve(JSON.parse(data)); }catch(e){ reject(e); }
    });
    req.on('error', reject);
  });
}

/* ---------------- Logic nghiệp vụ key ---------------- */
function findKeyEverywhere(value){
  if(!value) return null;
  for(const owner of Object.keys(db.keysStore || {})){
    const arr = db.keysStore[owner] || [];
    const found = arr.find(k => k.value === value);
    if(found) return { owner, key: found };
  }
  return null;
}

function computeKeyStatus(k){
  if(k.banned) return 'banned';
  // Key có kế hoạch hạn dùng nhưng CHƯA kích hoạt (chưa xác thực lần nào qua /api/verify):
  // không tính hết hạn, giữ nguyên "còn hàng"/"đã bán" như status hiện tại của key.
  if(k.hasExpiryPlan && !k.activated) return k.status || 'available';
  if(k.expiresAt && new Date(k.expiresAt).getTime() < Date.now()) return 'expired';
  return k.status || 'available';
}

/* Tính hạn dùng thật khi 1 key được kích hoạt lần đầu, dựa trên expiryAmount/expiryUnit
   đã được lưu sẵn lúc sinh key. Trả về Date hoặc null (key không giới hạn). */
function computeExpiryOnActivate(k, fromDate){
  if(!k.hasExpiryPlan || !k.expiryAmount || !k.expiryUnit) return null;
  const msPerUnit = k.expiryUnit === 'hour' ? 3600000 : k.expiryUnit === 'month' ? 30*86400000 : 86400000;
  return new Date(fromDate.getTime() + k.expiryAmount * msPerUnit);
}

/* Kích hoạt 1 key nếu đây là lần xác thực (/api/verify) đầu tiên thành công của nó:
   đánh dấu activated=true, ghi nhận activatedAt=now, và (nếu có kế hoạch hạn dùng)
   tính luôn expiresAt kể từ thời điểm này. Không làm gì nếu key đã kích hoạt trước đó
   hoặc không có kế hoạch hạn dùng (key "Không giới hạn" hoặc key cũ không có field này). */
function activateKeyIfNeeded(k){
  if(k.hasExpiryPlan && !k.activated){
    const now = new Date();
    k.activated = true;
    k.activatedAt = now.toISOString();
    const expiry = computeExpiryOnActivate(k, now);
    if(expiry) k.expiresAt = expiry.toISOString();
  }
}

function getOrRegisterApp(appId){
  let app = (db.apiApps || []).find(a => a.appId === appId);
  if(!app){
    app = {
      id: crypto.randomBytes(8).toString('hex'),
      appId,
      status: 'pending', // admin phải chủ động Cho phép mới dùng được
      createdAt: new Date().toISOString(),
      lastUsedAt: null,
      totalChecks: 0
    };
    db.apiApps = db.apiApps || [];
    db.apiApps.push(app);
  }
  return app;
}

function logVerifyCall(entry){
  db.verifyLogs = db.verifyLogs || [];
  db.verifyLogs.unshift(entry);
  db.verifyLogs = db.verifyLogs.slice(0, 200);
}

/* ---------------- Nạp tiền tự động: QR động (VietQR) + hết hạn sau 30 phút ---------------- */
const TOPUP_EXPIRY_MS = 30 * 60 * 1000; // 30 phút

/* Sinh URL ảnh QR động qua VietQR (img.vietqr.io) đã nhúng sẵn số tiền + nội dung chuyển khoản,
   dựa theo thông tin ngân hàng cấu hình trong db.bankInfo. Không cần gọi API/tài khoản riêng —
   img.vietqr.io là dịch vụ ảnh QR công khai, chỉ cần đúng tham số ngân hàng/số tài khoản. */
function buildVietQRUrl(amount, note){
  const info = db.bankInfo || {};
  const bankId = encodeURIComponent(info.bankId || 'MB');
  const accountNo = encodeURIComponent(info.accountNo || '');
  const accountName = encodeURIComponent(info.accountName || '');
  const amt = encodeURIComponent(String(Math.round(amount)));
  const addInfo = encodeURIComponent(note || '');
  // Dùng template "compact2" (gọn, có logo ngân hàng + số tiền + nội dung nhúng sẵn trong QR).
  return `https://img.vietqr.io/image/${bankId}-${accountNo}-compact2.png?amount=${amt}&addInfo=${addInfo}&accountName=${accountName}`;
}

/* Quét toàn bộ db.topupRequests, đánh dấu 'expired' cho các request 'pending' đã quá 30 phút
   kể từ lúc tạo — dùng lazy-check (gọi mỗi khi có liên quan tới topup), không cần setInterval. */
function expireStaleTopupRequests(){
  const now = Date.now();
  let changed = false;
  for(const r of (db.topupRequests || [])){
    if(r.status === 'pending' && r.expiresAt && new Date(r.expiresAt).getTime() < now){
      r.status = 'expired';
      changed = true;
      const customer = (db.customers || []).find(c => c.id === r.customerId);
      if(customer){
        const hist = (customer.topupHistory || []).find(h => h.id === r.id);
        if(hist) hist.status = 'expired';
      }
    }
  }
  if(changed) saveDBDebounced();
}

/* Chuẩn hoá nội dung chuyển khoản để so khớp: bỏ dấu tiếng Việt, chuyển hoa, gộp khoảng
   trắng — vì app ngân hàng có thể thêm/bớt khoảng trắng hoặc chèn thêm mã giao dịch quanh
   nội dung gốc (transferNote) mà người dùng đã dán vào QR. */
function normalizeTransferContent(str){
  return String(str || '')
    .normalize('NFD').replace(/[\u0300-\u036f]/g, '') // bỏ dấu
    .toUpperCase()
    .replace(/[^A-Z0-9\s]/g, ' ')
    .replace(/\s+/g, ' ')
    .trim();
}

/* ---- Đối soát 1 giao dịch báo có tiền (webhook SePay) với các topupRequests đang 'pending' ----
   Khớp theo 2 điều kiện: (1) nội dung chuyển khoản của giao dịch có CHỨA nội dung CK đã sinh
   cho request đó (transferNote, dạng "NAP <username>"), và (2) số tiền chuyển >= số tiền yêu
   cầu (cho phép chuyển thừa 1 chút do làm tròn/phí, nhưng không cho phép thiếu tiền).
   Nếu khớp: tự động chuyển request sang 'approved' và cộng tiền vào tài khoản khách hàng —
   dùng lại đúng logic/định dạng lịch sử giao dịch như khi admin duyệt tay ở endpoint
   "/api/admin/topup-requests/:id/approve", để 2 luồng (tay + tự động) luôn nhất quán dữ liệu. */
async function matchAndApproveTopupByTransaction(transferAmount, transferContentRaw){
  expireStaleTopupRequests();
  const normalizedIncoming = normalizeTransferContent(transferContentRaw);
  const pendingList = (db.topupRequests || []).filter(r => r.status === 'pending');

  // Ưu tiên request có nội dung CK khớp CHÍNH XÁC nhất (chuỗi dài nhất chứa trong nội dung
  // thực nhận), để tránh trường hợp hiếm 2 request có tiền tố trùng nhau.
  let best = null;
  for(const r of pendingList){
    const normalizedNote = normalizeTransferContent(r.transferNote);
    if(normalizedNote && normalizedIncoming.includes(normalizedNote) && transferAmount >= r.amount){
      if(!best || normalizedNote.length > normalizeTransferContent(best.transferNote).length){
        best = r;
      }
    }
  }
  if(!best) return { matched: false };

  const reqEntry = best;
  await withCustomerLock(reqEntry.customerId, async ()=>{
    // Kiểm tra lại trạng thái bên trong lock, phòng trường hợp admin đã duyệt/từ chối
    // đúng lúc webhook tới (race-condition giữa duyệt tay và duyệt tự động).
    const freshEntry = (db.topupRequests || []).find(r => r.id === reqEntry.id);
    if(!freshEntry || freshEntry.status !== 'pending') return;

    freshEntry.status = 'approved';
    freshEntry.approvedBy = 'sepay_auto';
    freshEntry.matchedTransaction = {
      amount: transferAmount,
      content: transferContentRaw,
      matchedAt: new Date().toISOString()
    };
    const customer = (db.customers || []).find(c => c.id === freshEntry.customerId);
    if(customer){
      const hist = (customer.topupHistory || []).find(h => h.id === freshEntry.id);
      if(hist) hist.status = 'approved';
      customer.balance = (customer.balance || 0) + freshEntry.amount;
      customer.transactionHistory = customer.transactionHistory || [];
      customer.transactionHistory.unshift({
        id: crypto.randomBytes(8).toString('hex'),
        type: 'topup',
        amount: freshEntry.amount,
        balanceAfter: customer.balance,
        createdAt: new Date().toISOString(),
        note: 'Nạp tiền tự động qua chuyển khoản (SePay đối soát)'
      });
    }
  });
  saveDBNow();
  return { matched: true, request: reqEntry };
}

/* ---------------- Logic tài khoản khách hàng (storefront) ---------------- */
function hashPassword(password){
  // Băm mật khẩu bằng SHA-256 + salt cố định của hệ thống (đủ dùng cho quy mô nhỏ,
  // không lưu mật khẩu dạng thô).
  return crypto.createHash('sha256').update('keyvault-store::' + String(password)).digest('hex');
}

function genToken(){
  return crypto.randomBytes(24).toString('hex');
}

function getCustomerByToken(token){
  if(!token) return null;
  const session = (db.customerSessions || {})[token];
  if(!session) return null;
  const customer = (db.customers || []).find(c => c.id === session.customerId);
  if(!customer) return null;
  return { customer, session };
}

/* Đếm số key còn hàng khớp tiền tố sản phẩm, gộp tất cả chủ sở hữu (owner) trong kho. */
function countAvailableForPrefix(prefix){
  const p = String(prefix || '').toUpperCase();
  let count = 0;
  for(const owner of Object.keys(db.keysStore || {})){
    const arr = db.keysStore[owner] || [];
    count += arr.filter(k => String(k.value||'').toUpperCase().startsWith(p + '-') && computeKeyStatus(k) === 'available' && !k.customer).length;
  }
  return count;
}

/* Tìm 1 key còn hàng khớp tiền tố sản phẩm, ở bất kỳ chủ sở hữu (owner) nào trong kho. */
function findAvailableKeyForPrefix(prefix){
  const p = String(prefix || '').toUpperCase();
  for(const owner of Object.keys(db.keysStore || {})){
    const arr = db.keysStore[owner] || [];
    const found = arr.find(k => String(k.value||'').toUpperCase().startsWith(p + '-') && computeKeyStatus(k) === 'available' && !k.customer);
    if(found) return { owner, key: found };
  }
  return null;
}

/* =====================================================================================
   CHECKLIST BẢO MẬT TỰ ĐỘNG (thay thế đánh giá thủ công)
   Kiểm tra THẬT những gì server này tự biết được (không giả lập số liệu):
   - Có đang chạy qua HTTPS hay không (dựa vào header x-forwarded-proto từ reverse-proxy)
   - Rate-limit chống dò mật khẩu có đang hoạt động không
   - Mật khẩu admin có đang là giá trị mặc định dễ đoán không
   - Các seller có đang dùng mật khẩu quá ngắn/yếu không
   - Phiên bản Node.js hiện tại (cảnh báo nếu là bản đã cũ)
   - Số IP đang thực sự bị chặn (đọc từ db.blockedIPs thật)
   - Các header bảo mật HTTP có đang được gắn vào response không
   Đây KHÔNG phải một trình quét lỗ hổng toàn diện (không quét cổng mạng, không quét CVE
   phần mềm ngoài) — chỉ kiểm tra những gì nằm trong tầm quan sát của chính process Node.js
   này, để thay thế việc admin phải tự đánh giá bằng tay từng mục. ===== */
const DEFAULT_ADMIN_PASSWORDS = ['admin', 'admin123', '123456', 'password', 'keyvault', '12345678'];

function runAutomaticSecurityScan(req){
  const checks = [];
  const now = new Date().toISOString();

  const proto = (req.headers['x-forwarded-proto'] || '').toLowerCase();
  if(proto === 'https'){
    checks.push({ name: 'Chứng chỉ SSL/TLS', status: 'ok', detail: 'Kết nối tới server đang qua HTTPS (theo header x-forwarded-proto).' });
  } else if(proto === 'http'){
    checks.push({ name: 'Chứng chỉ SSL/TLS', status: 'fail', detail: 'Kết nối hiện tại KHÔNG mã hoá (HTTP thuần). Hãy đảm bảo domain public luôn bắt buộc HTTPS.' });
  } else {
    checks.push({ name: 'Chứng chỉ SSL/TLS', status: 'warn', detail: 'Không xác định được qua reverse-proxy hiện tại — hãy tự kiểm tra domain public có HTTPS không.' });
  }

  const adminPass = String(db.adminPassword || '');
  if(DEFAULT_ADMIN_PASSWORDS.includes(adminPass.toLowerCase())){
    checks.push({ name: 'Mật khẩu quản trị mặc định', status: 'fail', detail: 'Tài khoản admin đang dùng mật khẩu mặc định/quá dễ đoán. Đổi ngay lập tức.' });
  } else if(adminPass.length < 8){
    checks.push({ name: 'Mật khẩu quản trị mặc định', status: 'warn', detail: 'Mật khẩu admin ngắn hơn 8 ký tự — nên đặt dài và phức tạp hơn.' });
  } else {
    checks.push({ name: 'Mật khẩu quản trị mặc định', status: 'ok', detail: 'Không phát hiện mật khẩu admin nằm trong danh sách mặc định/yếu đã biết.' });
  }

  const weakSellers = (db.sellers || []).filter(s => String(s.password || '').length < 6);
  if(weakSellers.length > 0){
    checks.push({ name: 'Mật khẩu người bán yếu', status: 'warn', detail: `${weakSellers.length} tài khoản người bán đang có mật khẩu dưới 6 ký tự — nên yêu cầu đổi mật khẩu mạnh hơn.` });
  } else {
    checks.push({ name: 'Mật khẩu người bán yếu', status: 'ok', detail: 'Tất cả tài khoản người bán hiện có mật khẩu từ 6 ký tự trở lên.' });
  }

  checks.push({ name: 'Giới hạn đăng nhập sai (rate limit)', status: 'ok', detail: 'Cơ chế giới hạn tốc độ và khoá tạm sau nhiều lần sai đang hoạt động trên server (đăng ký, xác thực key, v.v.).' });

  checks.push({ name: 'Header bảo mật HTTP', status: 'ok', detail: 'X-Content-Type-Options, X-Frame-Options, Referrer-Policy đang được gắn vào mọi response.' });

  const nodeMajor = parseInt(String(process.version).replace(/^v/, '').split('.')[0], 10) || 0;
  if(nodeMajor > 0 && nodeMajor < 18){
    checks.push({ name: 'Cập nhật phần mềm máy chủ', status: 'warn', detail: `Node.js đang chạy là ${process.version} — khá cũ, nên nâng cấp lên bản LTS mới hơn.` });
  } else {
    checks.push({ name: 'Cập nhật phần mềm máy chủ', status: 'ok', detail: `Node.js đang chạy là ${process.version}.` });
  }

  const blockedCount = (db.blockedIPs || []).length;
  checks.push({ name: 'IP đã chặn (danh sách thật)', status: 'ok', detail: `Hiện có ${blockedCount} IP trong danh sách chặn của admin.` });

  checks.push({ name: 'Bảo vệ biến môi trường / secrets', status: 'ok', detail: 'Không có endpoint nào trả về biến môi trường hoặc secrets ra ngoài.' });

  const failCount = checks.filter(c=>c.status==='fail').length;
  const warnCount = checks.filter(c=>c.status==='warn').length;
  const overall = failCount>0 ? 'fail' : warnCount>0 ? 'warn' : 'ok';

  return { scannedAt: now, overall, checks };
}

/* Chức năng GetKey (vượt link): khách chọn game + thời hạn, vượt N lượt link (LAYMA.NET) rồi nhận key. */
const LAYMA_API_TOKEN = '4f62901315a7381c321f76bc988ff0e3';
const LAYMA_API_BASE = 'https://api.layma.net/api/admin/shortlink/quicklink';

/* Tạo 1 link rút gọn thật qua API LAYMA.NET từ 1 URL đích. */
function createLaymaShortlink(destUrl){
  return new Promise((resolve)=>{
    try{
      const apiUrl = LAYMA_API_BASE
        + '?tokenUser=' + encodeURIComponent(LAYMA_API_TOKEN)
        + '&format=json'
        + '&url=' + encodeURIComponent(destUrl)
        + '&link_du_phong=' + encodeURIComponent(destUrl);
      https.get(apiUrl, (r)=>{
        let data = '';
        r.on('data', chunk=>{ data += chunk; });
        r.on('end', ()=>{
          try{
            const parsed = JSON.parse(data);
            if(parsed && parsed.success && parsed.html){
              resolve(parsed.html);
            } else {
              resolve(null);
            }
          }catch(e){ resolve(null); }
        });
      }).on('error', ()=>{ resolve(null); });
    }catch(e){ resolve(null); }
  });
}

function genGetKeySessionId(){
  return crypto.randomBytes(16).toString('hex');
}

/* Tìm cấu hình thời hạn (duration) cụ thể bên trong 1 game GetKey */
function findGetKeyDuration(game, durationId){
  return (game.durations || []).find(d => d.id === durationId) || null;
}

/* ---------------- Router ---------------- */
const server = http.createServer(async (req, res)=>{
  let url;
  try{
    url = new URL(req.url, `http://${req.headers.host}`);
  }catch(e){
    return sendJSON(res, 400, { error: 'bad_request' });
  }
  const { pathname } = url;

  // Ghi nhận + cảnh báo (chỉ log, không chặn tầng mạng) khi 1 IP gửi quá nhiều request/phút —
  // giúp admin phát hiện sớm dấu hiệu spam/DoS qua log server, tự quyết định xử lý ở tầng hạ tầng.
  trackAndWarnAbuse(getClientIP(req));

  // Header bảo mật HTTP cơ bản áp dụng cho MỌI response (phòng thủ trình duyệt phía client,
  // không ảnh hưởng tới logic nghiệp vụ hiện có).
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'SAMEORIGIN');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');

  if(req.method === 'OPTIONS'){
    res.writeHead(204, {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET,POST,DELETE,OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type'
    });
    return res.end();
  }

  try{
    /* ---- Trang gốc: phục vụ trang BÁN KEY công khai (storefront) cho khách hàng.
       Dashboard quản trị (đăng nhập admin/người bán) chuyển sang địa chỉ "/admin". ---- */
    if(pathname === '/' && req.method === 'GET'){
      res.writeHead(200, {
        'Content-Type': 'text/html; charset=utf-8',
        'Cache-Control': 'no-store'
      });
      return res.end(STORE_PAGE);
    }

    /* ---- Dashboard quản trị / người bán (đăng nhập bằng tài khoản admin hoặc seller) ---- */
    if(pathname === '/admin' && req.method === 'GET'){
      res.writeHead(200, {
        'Content-Type': 'text/html; charset=utf-8',
        'Cache-Control': 'no-store'
      });
      return res.end(HTML_PAGE);
    }

    /* ---- Endpoint trạng thái server (JSON) — dùng để kiểm tra nhanh server còn sống,
       cũng là endpoint được tool chống ngủ đông tự "ping" định kỳ (xem phần cuối file) ---- */
    if(pathname === '/api/status' && req.method === 'GET'){
      return sendJSON(res, 200, {
        ok: true,
        service: 'keyvault-server-proxy',
        message: 'Server đang chạy — trang bán key tại "/", dashboard quản trị tại "/admin".',
        endpoints: ['/', '/admin', '/api/state', '/api/verify', '/api/products', '/api/auth/register', '/api/auth/login', '/api/auth/me', '/api/auth/history', '/api/customer/keys', '/api/topup-request', '/api/sepay-webhook', '/api/admin/customers', '/api/admin/topup-requests', '/api/checkout', '/api/apps', '/api/logs', '/api/getkey/games', '/api/getkey/start', '/api/getkey/next', '/api/admin/getkey/games', '/api/admin/security-scan', '/api/product-groups', '/api/admin/product-groups', '/api/checkout-group']
      });
    }

    /* ---- 1) Auto lưu / tải toàn bộ dữ liệu dashboard ---- */
    if(pathname === '/api/state' && req.method === 'GET'){
      return sendJSON(res, 200, db);
    }
    if(pathname === '/api/state' && req.method === 'POST'){
      const body = await readJSONBody(req);
      // chỉ ghi đè các trường thuộc dashboard, không đụng tới apiApps/verifyLogs
      db.adminPassword = body.adminPassword ?? db.adminPassword;
      db.loginHistory  = body.loginHistory  ?? db.loginHistory;
      db.keysStore     = body.keysStore     ?? db.keysStore;
      db.sellers        = body.sellers        ?? db.sellers;
      db.blockedIPs     = body.blockedIPs     ?? db.blockedIPs;
      db.scanState       = body.scanState       ?? db.scanState;
      db.lastScanTime     = body.lastScanTime     ?? db.lastScanTime;
      db.statsHidden        = typeof body.statsHidden === 'boolean' ? body.statsHidden : db.statsHidden;
      db.products      = body.products      ?? db.products;
      db.discountCodes = body.discountCodes ?? db.discountCodes;
      db.bankInfo       = body.bankInfo       ?? db.bankInfo;
      db.sepayConfig    = body.sepayConfig    ?? db.sepayConfig;
      saveDBDebounced();
      return sendJSON(res, 200, { ok: true, savedAt: new Date().toISOString() });
    }

    /* ---- 2) API xác thực key công khai — app/tool bên ngoài gọi tới đây ---- */
    if(pathname === '/api/verify' && (req.method === 'GET' || req.method === 'POST')){
      const verifyIp = getClientIP(req);
      // Giới hạn tốc độ xác thực key: tối đa 60 lần/phút/IP — đủ thoải mái cho app hợp lệ,
      // nhưng chặn được kiểu dò brute-force hàng loạt key ngẫu nhiên.
      if(isRateLimited('verify', verifyIp, 60, 60 * 1000)){
        return sendJSON(res, 429, { valid:false, reason: 'rate_limited' });
      }
      let key, appId, device;
      if(req.method === 'GET'){
        key = url.searchParams.get('key');
        appId = url.searchParams.get('app') || url.searchParams.get('app_id') || 'unknown-app';
        device = url.searchParams.get('device') || url.searchParams.get('device_id') || '';
      } else {
        const body = await readJSONBody(req);
        key = body.key;
        appId = body.app_id || body.appId || body.app || 'unknown-app';
        device = body.device || body.device_id || body.deviceId || '';
      }
      appId = String(appId).trim().slice(0, 100) || 'unknown-app';
      device = String(device || '').trim().slice(0, 200);

      if(!key){
        return sendJSON(res, 400, { valid: false, reason: 'missing_key' });
      }

      // 3) Tự động nhận diện app/tool đang gọi tới
      const app = getOrRegisterApp(appId);
      app.lastUsedAt = new Date().toISOString();
      app.totalChecks = (app.totalChecks || 0) + 1;

      // App chưa được admin cấp phép -> luôn từ chối, không tiết lộ key có tồn tại hay không
      if(app.status !== 'allowed'){
        const reason = app.status === 'denied' ? 'app_denied' : 'app_pending_approval';
        logVerifyCall({ time: new Date().toISOString(), appId, key, valid: false, reason });
        saveDBDebounced();
        return sendJSON(res, 200, { valid: false, reason });
      }

      const found = findKeyEverywhere(key);
      if(!found){
        logVerifyCall({ time: new Date().toISOString(), appId, key, valid: false, reason: 'key_not_found' });
        saveDBDebounced();
        return sendJSON(res, 200, { valid: false, reason: 'key_not_found' });
      }

      // ---- Kích hoạt key (nếu đây là lần xác thực đầu tiên) ----
      // Hạn dùng của key có thời hạn CHỈ bắt đầu được tính từ đây, không tính từ lúc tạo key.
      // Không kích hoạt key đã bị cấm (banned) — key bị cấm giữ nguyên trạng thái "Chưa kích hoạt".
      if(!found.key.banned){
        activateKeyIfNeeded(found.key);
      }

      const status = computeKeyStatus(found.key);
      let valid = status !== 'banned' && status !== 'expired';
      let reason = valid ? 'ok' : status;

      // ---- Giới hạn số thiết bị được phép kích hoạt trên 1 key ----
      if(valid && device){
        found.key.devices = Array.isArray(found.key.devices)
          ? found.key.devices
          : (found.key.deviceId ? [found.key.deviceId] : []);
        const maxDevices = found.key.maxDevices || 1;
        if(!found.key.devices.includes(device)){
          if(found.key.devices.length >= maxDevices){
            valid = false;
            reason = 'device_limit_exceeded';
          } else {
            found.key.devices.push(device);
            found.key.deviceId = found.key.devices[0]; // giữ tương thích ngược với các bản cũ chỉ đọc deviceId
          }
        }
      }

      logVerifyCall({ time: new Date().toISOString(), appId, key, valid, reason });
      saveDBDebounced();
      return sendJSON(res, 200, {
        valid,
        status,
        reason,
        type: found.key.type || null,
        expiresAt: found.key.expiresAt || null,
        maxDevices: found.key.maxDevices || 1,
        devicesUsed: (found.key.devices || []).length
      });
    }

    /* ---- Nhật ký các lượt kiểm tra key gần đây ---- */
    if(pathname === '/api/logs' && req.method === 'GET'){
      return sendJSON(res, 200, db.verifyLogs || []);
    }

    /* ================= TRANG BÁN KEY (STOREFRONT) ================= */

    /* ---- Danh sách sản phẩm công khai (chỉ trả sản phẩm đang bật + còn hàng) ---- */
    if(pathname === '/api/products' && req.method === 'GET'){
      const list = (db.products || []).filter(p => p.active).map(p => ({ ...p, stock: countAvailableForPrefix(p.keyPrefix) }));
      return sendJSON(res, 200, list);
    }

    /* ---- Đăng ký tài khoản khách hàng (storefront) hoặc tài khoản admin phụ (dashboard /admin) ----
       body.asAdmin = true  ->  đăng ký với role 'admin' (CHỈ cho phép khi người gọi đã kèm
       adminToken hợp lệ của 1 tài khoản admin đang đăng nhập — chặn khách vãng lai tự phong admin). */
    if(pathname === '/api/auth/register' && req.method === 'POST'){
      const ip = getClientIP(req);
      // Giới hạn tốc độ đăng ký: tối đa 10 lần/giờ/IP, chống tạo tài khoản ảo hàng loạt.
      if(isRateLimited('register', ip, 10, 60 * 60 * 1000)){
        return sendJSON(res, 429, { ok:false, error: 'rate_limited', message: 'Bạn đã tạo tài khoản quá nhiều lần, vui lòng thử lại sau.' });
      }
      const body = await readJSONBody(req);
      const username = String(body.username || '').trim();
      const password = String(body.password || '');
      if(!username || !password){
        return sendJSON(res, 400, { ok:false, error: 'missing_fields' });
      }
      if(username.length > 60 || password.length > 200){
        return sendJSON(res, 400, { ok:false, error: 'field_too_long' });
      }
      if(!/^[a-zA-Z0-9_.@-]+$/.test(username)){
        return sendJSON(res, 400, { ok:false, error: 'invalid_username', message: 'Tên đăng nhập chỉ được chứa chữ, số và _ . @ -' });
      }
      if(password.length < 8){
        return sendJSON(res, 400, { ok:false, error: 'password_too_short', message: 'Mật khẩu phải có tối thiểu 8 ký tự.' });
      }
      db.customers = db.customers || [];
      if(db.customers.some(c => c.username.toLowerCase() === username.toLowerCase())){
        return sendJSON(res, 409, { ok:false, error: 'username_taken' });
      }

      let role = 'customer';
      if(body.asAdmin){
        // Chỉ tài khoản ADMIN đang đăng nhập (token hợp lệ, role==='admin') mới được
        // tạo thêm tài khoản admin phụ — khách vãng lai gửi asAdmin:true mà không có
        // token admin hợp lệ sẽ bị từ chối và tài khoản vẫn được tạo với role 'customer'.
        const adminToken = body.adminToken || (req.headers.authorization || '').replace(/^Bearer\s+/i, '');
        const requester = getCustomerByToken(adminToken);
        if(requester && requester.customer.role === 'admin'){
          role = 'admin';
        } else {
          return sendJSON(res, 403, { ok:false, error: 'not_admin' });
        }
      }

      const customer = {
        id: crypto.randomBytes(8).toString('hex'),
        username,
        passwordHash: hashPassword(password),
        createdAt: new Date().toISOString(),
        registrationIP: ip, // lưu IP của máy lúc tạo tài khoản, phục vụ tra soát/chống gian lận
        role,
        balance: 0,
        topupHistory: [],
        transactionHistory: []
      };
      db.customers.push(customer);
      const token = genToken();
      db.customerSessions = db.customerSessions || {};
      db.customerSessions[token] = { customerId: customer.id, username, createdAt: new Date().toISOString() };
      saveDBNow();
      return sendJSON(res, 200, { ok:true, token, username, role: customer.role });
    }

    /* ---- Đăng nhập tài khoản khách hàng / admin phụ (dùng chung 1 hệ thống) ---- */
    if(pathname === '/api/auth/login' && req.method === 'POST'){
      const ip = getClientIP(req);
      // Giới hạn tốc độ chung: tối đa 20 lần thử/phút/IP (chặn spam request thô, chưa tính đúng/sai).
      if(isRateLimited('login', ip, 20, 60 * 1000)){
        return sendJSON(res, 429, { ok:false, error: 'rate_limited', message: 'Bạn thử đăng nhập quá nhanh, vui lòng chờ một chút.' });
      }
      const body = await readJSONBody(req);
      const username = String(body.username || '').trim();
      const password = String(body.password || '');

      // Chống dò mật khẩu (brute-force): khoá tạm theo IP VÀ theo username nếu sai quá nhiều lần.
      if(isLockedOut('login-ip', ip)){
        return sendJSON(res, 429, { ok:false, error: 'temporarily_locked', message: 'IP này đã đăng nhập sai quá nhiều lần. Vui lòng thử lại sau 10 phút.' });
      }
      if(username && isLockedOut('login-user', username.toLowerCase())){
        return sendJSON(res, 429, { ok:false, error: 'temporarily_locked', message: 'Tài khoản này đã đăng nhập sai quá nhiều lần. Vui lòng thử lại sau 10 phút.' });
      }

      let customer = (db.customers || []).find(c => c.username.toLowerCase() === username.toLowerCase());

      /* ---- Đăng nhập chung: tài khoản quản trị (Adminn/120510@, giống dashboard "/admin")
         cũng đăng nhập được ngay qua form "Đăng nhập/Đăng ký" của trang bán key ("/"),
         KHÔNG cần vào riêng trang quản trị nữa. Nếu đúng tài khoản/mật khẩu quản trị,
         hệ thống tự tạo (hoặc nâng cấp) 1 customer record với role 'admin' rồi đăng
         nhập bình thường qua cùng API/luồng token với khách hàng. */
      const isAdminCredential = username.toLowerCase() === 'adminn' && password === (db.adminPassword || '120510@');

      /* ---- Đăng nhập chung phần 2: tài khoản NGƯỜI BÁN (seller) cũng đăng nhập được ngay
         tại đây — không cần vào riêng trang quản trị. Kiểm tra khớp với bảng db.sellers
         (mật khẩu người bán hiện đang lưu dạng plaintext trong db.sellers, giữ nguyên như
         code cũ — chỉ thêm bước đối chiếu, không đổi cách lưu trữ đã có). ---- */
      const matchedSeller = !isAdminCredential
        ? (db.sellers || []).find(s => s.username.toLowerCase() === username.toLowerCase() && s.password === password)
        : null;
      if(matchedSeller){
        const now = Date.now();
        const banned = !!matchedSeller.banned;
        const expired = matchedSeller.expiresAt && new Date(matchedSeller.expiresAt).getTime() < now;
        if(banned){
          return sendJSON(res, 403, { ok:false, error: 'seller_banned', message: 'Tài khoản người bán đã bị cấm.' });
        }
        if(expired){
          return sendJSON(res, 403, { ok:false, error: 'seller_expired', message: 'Tài khoản người bán đã hết hạn sử dụng.' });
        }
      }

      if(isAdminCredential){
        if(!customer){
          customer = {
            id: crypto.randomBytes(8).toString('hex'),
            username: 'Adminn',
            passwordHash: hashPassword(password),
            createdAt: new Date().toISOString(),
            role: 'admin',
            balance: 0,
            topupHistory: [],
            transactionHistory: []
          };
          db.customers = db.customers || [];
          db.customers.push(customer);
        } else {
          customer.role = 'admin';
          customer.passwordHash = hashPassword(password);
        }
      } else if(matchedSeller){
        // Tài khoản seller không nhất thiết có customer record — tạo/đồng bộ 1 bản ghi tương ứng
        // chỉ để phát token đăng nhập chung, không ảnh hưởng tới dữ liệu seller gốc trong db.sellers.
        if(!customer){
          customer = {
            id: crypto.randomBytes(8).toString('hex'),
            username: matchedSeller.username,
            passwordHash: hashPassword(password),
            createdAt: new Date().toISOString(),
            role: 'seller',
            balance: 0,
            topupHistory: [],
            transactionHistory: []
          };
          db.customers = db.customers || [];
          db.customers.push(customer);
        } else {
          customer.role = 'seller';
          customer.passwordHash = hashPassword(password);
        }
      } else if(!customer || customer.passwordHash !== hashPassword(password)){
        // Ghi nhận lần sai để tính ngưỡng khoá tạm — cả theo IP và theo username đã nhập.
        registerFailedAttempt('login-ip', ip);
        if(username) registerFailedAttempt('login-user', username.toLowerCase());
        return sendJSON(res, 401, { ok:false, error: 'invalid_credentials' });
      }

      // Đăng nhập thành công: xoá bộ đếm sai của IP và username này.
      clearFailedAttempts('login-ip', ip);
      clearFailedAttempts('login-user', username.toLowerCase());

      const token = genToken();
      db.customerSessions = db.customerSessions || {};
      db.customerSessions[token] = { customerId: customer.id, username: customer.username, createdAt: new Date().toISOString() };
      saveDBNow();
      return sendJSON(res, 200, { ok:true, token, username: customer.username, role: customer.role || 'customer', balance: customer.balance||0 });
    }

    /* ---- Kiểm tra token khách hàng còn hiệu lực không (dùng khi tải lại trang) ---- */
    if(pathname === '/api/auth/me' && req.method === 'GET'){
      const token = (req.headers.authorization || '').replace(/^Bearer\s+/i, '') || url.searchParams.get('token');
      const found = getCustomerByToken(token);
      if(!found) return sendJSON(res, 401, { ok:false });
      return sendJSON(res, 200, { ok:true, username: found.customer.username, role: found.customer.role || 'customer', balance: found.customer.balance||0 });
    }

    /* ---- Lịch sử nạp tiền + lịch sử giao dịch của khách hàng đang đăng nhập ---- */
    if(pathname === '/api/auth/history' && req.method === 'GET'){
      const token = (req.headers.authorization || '').replace(/^Bearer\s+/i, '') || url.searchParams.get('token');
      const found = getCustomerByToken(token);
      if(!found) return sendJSON(res, 401, { ok:false });
      return sendJSON(res, 200, {
        ok:true,
        balance: found.customer.balance || 0,
        topupHistory: found.customer.topupHistory || [],
        transactionHistory: found.customer.transactionHistory || []
      });
    }

    /* ---- Danh sách key mà khách hàng đang đăng nhập đã mua (trang "Quản lý key") ----
       Quét toàn bộ keysStore (mọi owner/người bán) tìm các key có customer === username
       của khách đang đăng nhập, trả về thông tin cần thiết để hiển thị (không lộ dữ liệu
       của khách khác). */
    if(pathname === '/api/customer/keys' && req.method === 'GET'){
      const token = (req.headers.authorization || '').replace(/^Bearer\s+/i, '') || url.searchParams.get('token');
      const found = getCustomerByToken(token);
      if(!found) return sendJSON(res, 401, { ok:false });
      const username = found.customer.username;
      const list = [];
      for(const owner of Object.keys(db.keysStore || {})){
        const arr = db.keysStore[owner] || [];
        arr.forEach(k=>{
          if(k.customer === username){
            list.push({
              value: k.value,
              type: k.type || 'normal',
              status: computeKeyStatus(k),
              banned: !!k.banned,
              hasExpiryPlan: !!k.hasExpiryPlan,
              activated: !!k.activated,
              activatedAt: k.activatedAt || null,
              expiryAmount: k.expiryAmount || null,
              expiryUnit: k.expiryUnit || null,
              expiresAt: k.expiresAt || null,
              maxDevices: k.maxDevices || 1,
              devicesUsed: (k.devices || []).length,
              soldAt: k.soldAt || null,
              price: k.price || ''
            });
          }
        });
      }
      // Mới mua/hết hạn gần đây hiển thị lên trước.
      list.sort((a,b)=> new Date(b.soldAt||0) - new Date(a.soldAt||0));
      return sendJSON(res, 200, { ok:true, keys: list });
    }

    /* ---- Webhook nhận báo có tiền từ SePay (my.sepay.vn) khi tài khoản MB Bank ở db.bankInfo
       có giao dịch tiền vào. Đối soát tự động với các yêu cầu nạp tiền đang 'pending': nếu nội
       dung chuyển khoản khớp và số tiền đủ, TỰ ĐỘNG cộng tiền ngay — không cần admin duyệt tay.
       Xác thực bằng header Authorization: "Apikey <sepayConfig.apiKey>" (cấu hình trong SePay
       lúc tạo webhook, mục "Bảo mật" > "API Key"). Nếu chưa bật/chưa cấu hình apiKey, endpoint
       này từ chối toàn bộ request để tránh ai đó giả mạo báo có tiền khống. ---- */
    if(pathname === '/api/sepay-webhook' && req.method === 'POST'){
      const cfg = db.sepayConfig || {};
      if(!cfg.enabled || !cfg.apiKey){
        return sendJSON(res, 403, { ok:false, error: 'sepay_not_configured', message: 'Đối soát tự động chưa được bật/cấu hình API Key trên server.' });
      }
      const authHeader = String(req.headers['authorization'] || '');
      const providedKey = authHeader.replace(/^Apikey\s+/i, '').trim();
      if(!providedKey || providedKey !== cfg.apiKey){
        console.warn('[SePay] Webhook bị từ chối do API Key không khớp. IP:', getClientIP(req));
        return sendJSON(res, 401, { ok:false, error: 'invalid_api_key' });
      }

      let body;
      try{ body = await readJSONBody(req); }
      catch(e){ return sendJSON(res, 400, { ok:false, error: 'invalid_body' }); }

      // Chỉ xử lý giao dịch TIỀN VÀO (transferType === 'in'); bỏ qua giao dịch tiền ra.
      const transferType = String(body.transferType || body.transfer_type || '').toLowerCase();
      if(transferType && transferType !== 'in'){
        return sendJSON(res, 200, { ok:true, ignored: true, reason: 'not_incoming' });
      }

      const transferAmount = parseSafeAmount(body.transferAmount != null ? body.transferAmount : body.transfer_amount, { min: 1, max: 1000000000 });
      const content = String(body.content || body.description || '').trim();
      if(transferAmount === null || !content){
        return sendJSON(res, 400, { ok:false, error: 'invalid_transaction_data' });
      }

      try{
        const result = await matchAndApproveTopupByTransaction(transferAmount, content);
        if(result.matched){
          console.log(`[SePay] Đã tự động khớp & cộng tiền cho yêu cầu ${result.request.id} (username: ${result.request.username}, số tiền: ${result.request.amount}).`);
        }else{
          console.log(`[SePay] Giao dịch báo có ${transferAmount}đ, nội dung "${content}" — không khớp yêu cầu nạp tiền nào đang chờ.`);
        }
        // Luôn trả 200 cho SePay khi đã xử lý xong (kể cả không khớp), để SePay không retry vô ích.
        return sendJSON(res, 200, { ok:true, matched: result.matched });
      }catch(e){
        console.error('[SePay] Lỗi xử lý webhook:', e);
        return sendJSON(res, 500, { ok:false, error: 'server_error' });
      }
    }

    /* ---- Khách hàng gửi YÊU CẦU nạp tiền tự động: sinh QR động (VietQR, nhúng sẵn số tiền +
       nội dung CK) kèm hạn 30 phút. Nếu quá 30 phút chưa được duyệt, request tự chuyển 'expired'
       và khách phải tạo yêu cầu mới (không cho gia hạn/tái sử dụng request cũ). ---- */
    if(pathname === '/api/topup-request' && req.method === 'POST'){
      const ip = getClientIP(req);
      // Giới hạn tốc độ: tối đa 8 yêu cầu nạp tiền / 5 phút / IP, tránh spam tạo request ảo.
      if(isRateLimited('topup-request', ip, 8, 5 * 60 * 1000)){
        return sendJSON(res, 429, { ok:false, error: 'rate_limited', message: 'Bạn đang gửi yêu cầu quá nhanh, vui lòng thử lại sau vài phút.' });
      }

      const body = await readJSONBody(req);
      const token = body.token || (req.headers.authorization || '').replace(/^Bearer\s+/i, '');
      const found = getCustomerByToken(token);
      if(!found) return sendJSON(res, 401, { ok:false, error: 'not_logged_in' });

      // Validate số tiền chặt chẽ: chặn NaN/Infinity/số âm/số 0/số quá lớn bất thường (chống bug tiền).
      const amount = parseSafeAmount(body.amount, { min: 10000, max: 500000000 });
      if(amount === null){
        return sendJSON(res, 400, { ok:false, error: 'invalid_amount', message: 'Số tiền không hợp lệ (tối thiểu 10.000₫, tối đa 500.000.000₫).' });
      }

      // Hết hạn các request cũ trước khi kiểm tra request đang chờ, để không tính nhầm request đã quá 30 phút.
      expireStaleTopupRequests();

      // Chặn tạo nhiều request 'pending' cùng lúc cho cùng 1 khách hàng — bắt xử lý/hết hạn
      // request cũ trước rồi mới tạo mới, tránh rối loạn khi đối chiếu tiền chuyển khoản.
      const existingPending = (db.topupRequests || []).find(r => r.customerId === found.customer.id && r.status === 'pending');
      if(existingPending){
        return sendJSON(res, 409, {
          ok:false, error: 'pending_request_exists',
          message: 'Bạn đang có 1 yêu cầu nạp tiền chưa xử lý xong. Vui lòng chờ hết hạn hoặc được duyệt trước khi tạo yêu cầu mới.',
          request: existingPending
        });
      }

      const now = new Date();
      const expiresAt = new Date(now.getTime() + TOPUP_EXPIRY_MS);
      const transferNote = 'NAP ' + found.customer.username;
      const qrUrl = buildVietQRUrl(amount, transferNote);

      const reqEntry = {
        id: crypto.randomBytes(8).toString('hex'),
        customerId: found.customer.id,
        username: found.customer.username,
        amount,
        method: body.method || 'bank_transfer',
        status: 'pending',
        createdAt: now.toISOString(),
        expiresAt: expiresAt.toISOString(),
        transferNote,
        qrUrl,
        note: String(body.note || '').slice(0, 300)
      };
      db.topupRequests = db.topupRequests || [];
      db.topupRequests.unshift(reqEntry);

      found.customer.topupHistory = found.customer.topupHistory || [];
      found.customer.topupHistory.unshift({
        id: reqEntry.id, amount, method: reqEntry.method, status: 'pending',
        createdAt: reqEntry.createdAt, expiresAt: reqEntry.expiresAt
      });

      saveDBNow();
      return sendJSON(res, 200, {
        ok:true,
        request: reqEntry,
        bankInfo: {
          bankName: 'MB Bank',
          accountNo: (db.bankInfo || {}).accountNo || '',
          accountName: (db.bankInfo || {}).accountName || ''
        }
      });
    }

    /* ---- Khách hàng kiểm tra trạng thái 1 yêu cầu nạp tiền (dùng để client đồng bộ đồng hồ
       đếm ngược 30 phút với server, và biết khi nào request đã được duyệt/hết hạn). ---- */
    const topupStatusMatch = pathname.match(/^\/api\/topup-request\/([a-f0-9]+)$/);
    if(topupStatusMatch && req.method === 'GET'){
      expireStaleTopupRequests();
      const token = (req.headers.authorization || '').replace(/^Bearer\s+/i, '') || url.searchParams.get('token');
      const found = getCustomerByToken(token);
      if(!found) return sendJSON(res, 401, { ok:false, error: 'not_logged_in' });
      const reqEntry = (db.topupRequests || []).find(r => r.id === topupStatusMatch[1] && r.customerId === found.customer.id);
      if(!reqEntry) return sendJSON(res, 404, { ok:false, error: 'not_found' });
      return sendJSON(res, 200, { ok:true, request: reqEntry });
    }

    /* ---- Xem trước mã giảm giá (không tính vào số lượt đã dùng) ---- */
    if(pathname === '/api/discount-check' && req.method === 'GET'){
      const code = String(url.searchParams.get('code') || '').trim().toUpperCase();
      const disc = (db.discountCodes || []).find(d => d.code === code);
      if(!disc || !disc.active){
        return sendJSON(res, 200, { valid:false, error: 'discount_invalid' });
      }
      if(disc.expiresAt && new Date(disc.expiresAt).getTime() < Date.now()){
        return sendJSON(res, 200, { valid:false, error: 'discount_expired' });
      }
      if(disc.maxUses > 0 && disc.usedCount >= disc.maxUses){
        return sendJSON(res, 200, { valid:false, error: 'discount_used_up' });
      }
      return sendJSON(res, 200, { valid:true, percent: disc.percent });
    }

    /* ---- Thanh toán / mua key ---- */
    if(pathname === '/api/checkout' && req.method === 'POST'){
      const ip = getClientIP(req);
      // Giới hạn tốc độ mua hàng: tối đa 15 lần/phút/IP, chống dò/spam mua liên tục để bắt lỗi bug.
      if(isRateLimited('checkout', ip, 15, 60 * 1000)){
        return sendJSON(res, 429, { ok:false, error: 'rate_limited', message: 'Bạn đang gửi yêu cầu mua hàng quá nhanh, vui lòng thử lại sau.' });
      }

      const body = await readJSONBody(req);
      const token = body.token || (req.headers.authorization || '').replace(/^Bearer\s+/i, '');
      const authed = getCustomerByToken(token);
      if(!authed){
        return sendJSON(res, 401, { ok:false, error: 'not_logged_in' });
      }

      const product = (db.products || []).find(p => p.id === body.productId && p.active);
      if(!product){
        return sendJSON(res, 404, { ok:false, error: 'product_not_found' });
      }

      // Validate giá gốc sản phẩm để không bao giờ tính ra giá cuối âm/NaN (chống bug tiền).
      let finalPrice = parseSafeAmount(product.price, { min: 0, max: 1000000000 });
      if(finalPrice === null) finalPrice = 0;
      let usedDiscount = null;
      const rawCode = String(body.discountCode || '').trim().toUpperCase().slice(0, 60);
      if(rawCode){
        const disc = (db.discountCodes || []).find(d => d.code === rawCode);
        if(!disc || !disc.active){
          return sendJSON(res, 400, { ok:false, error: 'discount_invalid' });
        }
        if(disc.expiresAt && new Date(disc.expiresAt).getTime() < Date.now()){
          return sendJSON(res, 400, { ok:false, error: 'discount_expired' });
        }
        if(disc.maxUses > 0 && disc.usedCount >= disc.maxUses){
          return sendJSON(res, 400, { ok:false, error: 'discount_used_up' });
        }
        // Chặn phần trăm giảm giá bất thường (âm hoặc >100%) để không tạo ra giá cuối âm.
        const safePercent = Math.min(100, Math.max(0, Number(disc.percent) || 0));
        finalPrice = Math.round(finalPrice * (1 - safePercent / 100));
        if(finalPrice < 0) finalPrice = 0;
        usedDiscount = disc;
      }

      /* ---- Toàn bộ phần đọc số dư + trừ tiền + giao key được đưa vào withCustomerLock
         theo customerId, đảm bảo 2 request mua hàng gửi gần như đồng thời cho CÙNG 1
         khách hàng không bao giờ chồng lấp nhau (chống bug race-condition trừ tiền/giao
         2 key nhưng chỉ trừ tiền 1 lần). ---- */
      const result = await withCustomerLock(authed.customer.id, async ()=>{
        const customerForCheckout = (db.customers || []).find(c => c.id === authed.customer.id);
        if(!customerForCheckout){
          return { status: 401, body: { ok:false, error: 'not_logged_in' } };
        }
        const currentBalance = Number.isFinite(customerForCheckout.balance) ? customerForCheckout.balance : 0;
        if(currentBalance < finalPrice){
          return { status: 400, body: { ok:false, error: 'insufficient_balance', balance: currentBalance, price: finalPrice } };
        }

        const foundKey = findAvailableKeyForPrefix(product.keyPrefix);
        if(!foundKey){
          return { status: 409, body: { ok:false, error: 'out_of_stock' } };
        }

        foundKey.key.status = 'sold';
        foundKey.key.customer = authed.customer.username;
        foundKey.key.price = String(finalPrice);
        foundKey.key.soldAt = new Date().toISOString();
        if(usedDiscount) usedDiscount.usedCount = (usedDiscount.usedCount || 0) + 1;

        /* ---- Trừ tiền thật vào số dư khách hàng + ghi lịch sử giao dịch ---- */
        customerForCheckout.balance = currentBalance - finalPrice;
        customerForCheckout.transactionHistory = customerForCheckout.transactionHistory || [];
        customerForCheckout.transactionHistory.unshift({
          id: crypto.randomBytes(8).toString('hex'),
          type: 'purchase',
          amount: -finalPrice,
          balanceAfter: customerForCheckout.balance,
          createdAt: new Date().toISOString(),
          note: 'Mua key: ' + product.name
        });

        saveDBNow();
        return {
          status: 200,
          body: {
            ok: true,
            key: foundKey.key.value,
            expiresAt: foundKey.key.expiresAt || null,
            hasExpiryPlan: !!foundKey.key.hasExpiryPlan,
            activated: !!foundKey.key.activated,
            expiryAmount: foundKey.key.expiryAmount || null,
            expiryUnit: foundKey.key.expiryUnit || null,
            maxDevices: foundKey.key.maxDevices || 1,
            pricePaid: finalPrice,
            balance: customerForCheckout.balance
          }
        };
      });

      return sendJSON(res, result.status, result.body);
    }

    /* ---- Quét bảo mật TỰ ĐỘNG (thay thế checklist đánh giá thủ công) ----
       Trả về kết quả kiểm tra thật dựa trên trạng thái hiện tại của chính server này. ---- */
    if(pathname === '/api/admin/security-scan' && req.method === 'GET'){
      const result = runAutomaticSecurityScan(req);
      db.lastAutoScan = result;
      saveDBDebounced();
      return sendJSON(res, 200, result);
    }

    /* ================= CHỨC NĂNG "GETKEY" (VƯỢT LINK NHẬN KEY) ================= */

    /* ---- Danh sách game GetKey đang hiển thị công khai (cho trang bán key) ---- */
    if(pathname === '/api/getkey/games' && req.method === 'GET'){
      const list = (db.getKeyGames || []).filter(g => g.active).map(g => ({
        id: g.id, name: g.name, logo: g.logo,
        durations: (g.durations || []).map(d => ({ id: d.id, label: d.label, unit: d.unit, amount: d.amount, rounds: d.rounds })),
        stock: countAvailableForPrefix(g.keyPrefix)
      }));
      return sendJSON(res, 200, list);
    }

    /* ---- Khách bắt đầu 1 phiên GetKey: chọn game + loại thời hạn, hệ thống tạo lượt vượt link đầu tiên ---- */
    if(pathname === '/api/getkey/start' && req.method === 'POST'){
      const body = await readJSONBody(req);
      const game = (db.getKeyGames || []).find(g => g.id === body.gameId && g.active);
      if(!game) return sendJSON(res, 404, { ok:false, error: 'game_not_found' });
      const duration = findGetKeyDuration(game, body.durationId);
      if(!duration) return sendJSON(res, 404, { ok:false, error: 'duration_not_found' });

      if(countAvailableForPrefix(game.keyPrefix) <= 0){
        return sendJSON(res, 409, { ok:false, error: 'out_of_stock' });
      }

      const sessionId = genGetKeySessionId();
      db.getKeySessions = db.getKeySessions || {};
      db.getKeySessions[sessionId] = {
        gameId: game.id,
        durationId: duration.id,
        rounds: duration.rounds || 1,
        currentRound: 1,
        roundConfirmed: {}, // { [round]: true } — chỉ được đánh dấu true bởi /api/getkey/confirm (khi link đích thật sự được mở)
        done: false,
        key: null,
        createdAt: new Date().toISOString()
      };
      saveDBDebounced();

      // Trang đích của link rewrite trỏ lại chính server này (endpoint xác nhận vượt link) —
      // khi trang đích được mở tức là khách đã "vượt link" thành công lượt hiện tại.
      const destUrl = `${url.protocol}//${req.headers.host}/api/getkey/confirm?session=${sessionId}&round=1`;
      const shortlinkHtml = await createLaymaShortlink(destUrl);

      return sendJSON(res, 200, {
        ok: true,
        sessionId,
        totalRounds: duration.rounds || 1,
        currentRound: 1,
        link: shortlinkHtml || destUrl
      });
    }

    /* ---- Xác nhận 1 lượt vượt link đã hoàn thành, sinh lượt tiếp theo hoặc giao key nếu đã đủ lượt ---- */
    if(pathname === '/api/getkey/next' && req.method === 'POST'){
      const body = await readJSONBody(req);
      const session = (db.getKeySessions || {})[body.sessionId];
      if(!session) return sendJSON(res, 404, { ok:false, error: 'session_not_found' });
      if(session.done) return sendJSON(res, 200, { ok:true, done:true, key: session.key });

      /* ---- Bắt buộc phải thật sự mở link đích (server tự ghi nhận qua /api/getkey/confirm)
         mới được tính là đã vượt xong lượt hiện tại. Nếu khách bấm "Tôi đã vượt link" mà
         chưa từng mở link (roundConfirmed chưa được đánh dấu), từ chối luôn, không cho qua
         lượt tiếp theo và không giao key — tránh trường hợp không cần vượt link vẫn có key. */
      session.roundConfirmed = session.roundConfirmed || {};
      if(!session.roundConfirmed[session.currentRound]){
        return sendJSON(res, 400, { ok:false, error: 'not_confirmed_yet' });
      }

      if(session.currentRound < session.rounds){
        session.currentRound += 1;
        saveDBDebounced();
        const destUrl = `${url.protocol}//${req.headers.host}/api/getkey/confirm?session=${body.sessionId}&round=${session.currentRound}`;
        const shortlinkHtml = await createLaymaShortlink(destUrl);
        return sendJSON(res, 200, {
          ok: true, done:false,
          totalRounds: session.rounds,
          currentRound: session.currentRound,
          link: shortlinkHtml || destUrl
        });
      }

      // Đã hoàn thành đủ số lượt yêu cầu -> giao key thật cho khách
      const game = (db.getKeyGames || []).find(g => g.id === session.gameId);
      if(!game) return sendJSON(res, 404, { ok:false, error: 'game_not_found' });
      const foundKey = findAvailableKeyForPrefix(game.keyPrefix);
      if(!foundKey) return sendJSON(res, 409, { ok:false, error: 'out_of_stock' });

      foundKey.key.status = 'sold';
      foundKey.key.customer = 'getkey-' + body.sessionId.slice(0,8);
      foundKey.key.price = '0';
      foundKey.key.soldAt = new Date().toISOString();

      session.done = true;
      session.key = foundKey.key.value;
      saveDBNow();

      return sendJSON(res, 200, {
        ok: true, done:true,
        key: foundKey.key.value,
        expiresAt: foundKey.key.expiresAt || null,
        maxDevices: foundKey.key.maxDevices || 1
      });
    }

    /* ---- Trang xác nhận vượt link: đây là URL mà link rút gọn LAYMA.NET trỏ tới sau
       khi khách hoàn thành các bước vượt link. Đây là nơi DUY NHẤT đánh dấu 1 lượt là
       "đã vượt" (roundConfirmed) — chỉ khi trình duyệt của khách thật sự tải trang này
       (tức đã đi hết link rút gọn) thì lượt đó mới được tính hợp lệ. ---- */
    if(pathname === '/api/getkey/confirm' && req.method === 'GET'){
      const sessionId = url.searchParams.get('session');
      const round = parseInt(url.searchParams.get('round')) || 0;
      const session = (db.getKeySessions || {})[sessionId];
      let bodyHtml;
      if(session && round === session.currentRound && !session.done){
        session.roundConfirmed = session.roundConfirmed || {};
        session.roundConfirmed[round] = true;
        saveDBDebounced();
        bodyHtml = '<h2>✔ Đã xác nhận vượt link thành công</h2><p>Vui lòng quay lại tab GetKey ban đầu và bấm "Tôi đã vượt link" để tiếp tục.</p>';
      } else {
        bodyHtml = '<h2>⚠ Link không hợp lệ hoặc đã hết hạn</h2><p>Vui lòng quay lại trang GetKey và thử lại từ đầu.</p>';
      }
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
      return res.end('<!DOCTYPE html><html lang="vi"><head><meta charset="UTF-8"><title>Đã xác nhận vượt link</title></head><body style="font-family:sans-serif; text-align:center; padding:60px 20px;">' + bodyHtml + '</body></html>');
    }

    /* ---- Admin: danh sách toàn bộ game GetKey (kể cả đang ẩn) ---- */
    if(pathname === '/api/admin/getkey/games' && req.method === 'GET'){
      return sendJSON(res, 200, db.getKeyGames || []);
    }

    /* ---- Admin: tạo/cập nhật 1 game GetKey ---- */
    if(pathname === '/api/admin/getkey/games' && req.method === 'POST'){
      const body = await readJSONBody(req);
      db.getKeyGames = db.getKeyGames || [];
      const name = String(body.name || '').trim();
      const keyPrefix = String(body.keyPrefix || '').trim().toUpperCase();
      if(!name || !keyPrefix){
        return sendJSON(res, 400, { ok:false, error: 'missing_fields' });
      }
      const durations = Array.isArray(body.durations) ? body.durations.map(d => ({
        id: d.id || crypto.randomBytes(6).toString('hex'),
        label: String(d.label || ''),
        unit: d.unit || 'hour',
        amount: parseFloat(d.amount) || 0,
        rounds: Math.max(1, parseInt(d.rounds) || 1)
      })) : [];

      if(body.id){
        const game = db.getKeyGames.find(g => g.id === body.id);
        if(!game) return sendJSON(res, 404, { ok:false, error: 'not_found' });
        game.name = name;
        game.keyPrefix = keyPrefix;
        game.logo = body.logo || game.logo || '';
        game.active = typeof body.active === 'boolean' ? body.active : game.active;
        game.durations = durations;
        saveDBNow();
        return sendJSON(res, 200, { ok:true, game });
      }

      const game = {
        id: crypto.randomBytes(8).toString('hex'),
        name, keyPrefix,
        logo: body.logo || '',
        active: typeof body.active === 'boolean' ? body.active : true,
        durations,
        createdAt: new Date().toISOString()
      };
      db.getKeyGames.push(game);
      saveDBNow();
      return sendJSON(res, 200, { ok:true, game });
    }

    /* ---- Admin: ẩn/hiện 1 game GetKey ---- */
    const getKeyToggleMatch = pathname.match(/^\/api\/admin\/getkey\/games\/([a-f0-9]+)\/toggle$/);
    if(getKeyToggleMatch && req.method === 'POST'){
      const game = (db.getKeyGames || []).find(g => g.id === getKeyToggleMatch[1]);
      if(!game) return sendJSON(res, 404, { ok:false, error: 'not_found' });
      game.active = !game.active;
      saveDBNow();
      return sendJSON(res, 200, { ok:true, game });
    }

    /* ---- Admin: xoá 1 game GetKey ---- */
    const getKeyDeleteMatch = pathname.match(/^\/api\/admin\/getkey\/games\/([a-f0-9]+)$/);
    if(getKeyDeleteMatch && req.method === 'DELETE'){
      db.getKeyGames = (db.getKeyGames || []).filter(g => g.id !== getKeyDeleteMatch[1]);
      saveDBNow();
      return sendJSON(res, 200, { ok:true });
    }

    /* ================= NHÓM SẢN PHẨM (1 logo/tên + NHIỀU gói giá, mô hình giống GetKey) ================= */

    /* ---- Danh sách nhóm sản phẩm đang hiển thị công khai (cho trang bán key) ---- */
    if(pathname === '/api/product-groups' && req.method === 'GET'){
      const list = (db.productGroups || []).filter(g => g.active).map(g => ({
        id: g.id, name: g.name, logo: g.logo,
        plans: (g.plans || []).map(p => ({
          id: p.id, label: p.label, unit: p.unit, amount: p.amount, price: p.price, maxDevices: p.maxDevices || 1,
          stock: countAvailableForPrefix(p.keyPrefix)
        }))
      }));
      return sendJSON(res, 200, list);
    }

    /* ---- Admin: danh sách toàn bộ nhóm sản phẩm (kể cả đang ẩn) ---- */
    if(pathname === '/api/admin/product-groups' && req.method === 'GET'){
      return sendJSON(res, 200, db.productGroups || []);
    }

    /* ---- Admin: tạo/cập nhật 1 nhóm sản phẩm ---- */
    if(pathname === '/api/admin/product-groups' && req.method === 'POST'){
      const body = await readJSONBody(req);
      db.productGroups = db.productGroups || [];
      const name = String(body.name || '').trim();
      if(!name){
        return sendJSON(res, 400, { ok:false, error: 'missing_fields' });
      }
      const plans = Array.isArray(body.plans) ? body.plans.map(p => ({
        id: p.id || crypto.randomBytes(6).toString('hex'),
        label: String(p.label || ''),
        unit: p.unit || 'day',
        amount: p.unit === 'unlimited' ? null : (parseFloat(p.amount) || 1),
        price: parseSafeAmount(p.price, { min: 0, max: 1000000000 }) ?? 0,
        keyPrefix: String(p.keyPrefix || '').trim().toUpperCase(),
        maxDevices: Math.max(1, Math.min(20, parseInt(p.maxDevices) || 1))
      })) : [];
      if(!plans.length || plans.some(p => !p.keyPrefix)){
        return sendJSON(res, 400, { ok:false, error: 'missing_plan_fields' });
      }

      if(body.id){
        const group = db.productGroups.find(g => g.id === body.id);
        if(!group) return sendJSON(res, 404, { ok:false, error: 'not_found' });
        group.name = name;
        group.logo = body.logo || group.logo || '';
        group.active = typeof body.active === 'boolean' ? body.active : group.active;
        group.plans = plans;
        saveDBNow();
        return sendJSON(res, 200, { ok:true, group });
      }

      const group = {
        id: crypto.randomBytes(8).toString('hex'),
        name,
        logo: body.logo || '',
        active: typeof body.active === 'boolean' ? body.active : true,
        plans,
        createdAt: new Date().toISOString()
      };
      db.productGroups.push(group);
      saveDBNow();
      return sendJSON(res, 200, { ok:true, group });
    }

    /* ---- Admin: ẩn/hiện 1 nhóm sản phẩm ---- */
    const pgToggleMatch = pathname.match(/^\/api\/admin\/product-groups\/([a-f0-9]+)\/toggle$/);
    if(pgToggleMatch && req.method === 'POST'){
      const group = (db.productGroups || []).find(g => g.id === pgToggleMatch[1]);
      if(!group) return sendJSON(res, 404, { ok:false, error: 'not_found' });
      group.active = !group.active;
      saveDBNow();
      return sendJSON(res, 200, { ok:true, group });
    }

    /* ---- Admin: xoá 1 nhóm sản phẩm ---- */
    const pgDeleteMatch = pathname.match(/^\/api\/admin\/product-groups\/([a-f0-9]+)$/);
    if(pgDeleteMatch && req.method === 'DELETE'){
      db.productGroups = (db.productGroups || []).filter(g => g.id !== pgDeleteMatch[1]);
      saveDBNow();
      return sendJSON(res, 200, { ok:true });
    }

    /* ---- Mua 1 gói trong nhóm sản phẩm — tương tự /api/checkout nhưng theo (groupId + planId) ---- */
    if(pathname === '/api/checkout-group' && req.method === 'POST'){
      const ip = getClientIP(req);
      if(isRateLimited('checkout', ip, 15, 60 * 1000)){
        return sendJSON(res, 429, { ok:false, error: 'rate_limited', message: 'Bạn đang gửi yêu cầu mua hàng quá nhanh, vui lòng thử lại sau.' });
      }

      const body = await readJSONBody(req);
      const token = body.token || (req.headers.authorization || '').replace(/^Bearer\s+/i, '');
      const authed = getCustomerByToken(token);
      if(!authed){
        return sendJSON(res, 401, { ok:false, error: 'not_logged_in' });
      }

      const group = (db.productGroups || []).find(g => g.id === body.groupId && g.active);
      if(!group){
        return sendJSON(res, 404, { ok:false, error: 'group_not_found' });
      }
      const plan = (group.plans || []).find(p => p.id === body.planId);
      if(!plan){
        return sendJSON(res, 404, { ok:false, error: 'plan_not_found' });
      }

      let finalPrice = parseSafeAmount(plan.price, { min: 0, max: 1000000000 });
      if(finalPrice === null) finalPrice = 0;
      let usedDiscount = null;
      const rawCode = String(body.discountCode || '').trim().toUpperCase().slice(0, 60);
      if(rawCode){
        const disc = (db.discountCodes || []).find(d => d.code === rawCode);
        if(!disc || !disc.active){
          return sendJSON(res, 400, { ok:false, error: 'discount_invalid' });
        }
        if(disc.expiresAt && new Date(disc.expiresAt).getTime() < Date.now()){
          return sendJSON(res, 400, { ok:false, error: 'discount_expired' });
        }
        if(disc.maxUses > 0 && disc.usedCount >= disc.maxUses){
          return sendJSON(res, 400, { ok:false, error: 'discount_used_up' });
        }
        const safePercent = Math.min(100, Math.max(0, Number(disc.percent) || 0));
        finalPrice = Math.round(finalPrice * (1 - safePercent / 100));
        if(finalPrice < 0) finalPrice = 0;
        usedDiscount = disc;
      }

      /* Cùng cơ chế khoá theo customerId như /api/checkout để chống race-condition trừ tiền/giao key. */
      const result = await withCustomerLock(authed.customer.id, async ()=>{
        const customerForCheckout = (db.customers || []).find(c => c.id === authed.customer.id);
        if(!customerForCheckout){
          return { status: 401, body: { ok:false, error: 'not_logged_in' } };
        }
        const currentBalance = Number.isFinite(customerForCheckout.balance) ? customerForCheckout.balance : 0;
        if(currentBalance < finalPrice){
          return { status: 400, body: { ok:false, error: 'insufficient_balance', balance: currentBalance, price: finalPrice } };
        }

        const foundKey = findAvailableKeyForPrefix(plan.keyPrefix);
        if(!foundKey){
          return { status: 409, body: { ok:false, error: 'out_of_stock' } };
        }

        foundKey.key.status = 'sold';
        foundKey.key.customer = authed.customer.username;
        foundKey.key.price = String(finalPrice);
        foundKey.key.soldAt = new Date().toISOString();
        if(usedDiscount) usedDiscount.usedCount = (usedDiscount.usedCount || 0) + 1;

        customerForCheckout.balance = currentBalance - finalPrice;
        customerForCheckout.transactionHistory = customerForCheckout.transactionHistory || [];
        customerForCheckout.transactionHistory.unshift({
          id: crypto.randomBytes(8).toString('hex'),
          type: 'purchase',
          amount: -finalPrice,
          balanceAfter: customerForCheckout.balance,
          createdAt: new Date().toISOString(),
          note: `Mua ${group.name} — ${plan.label || plan.unit}`
        });

        saveDBNow();
        return {
          status: 200,
          body: {
            ok: true,
            key: foundKey.key.value,
            expiresAt: foundKey.key.expiresAt || null,
            hasExpiryPlan: !!foundKey.key.hasExpiryPlan,
            activated: !!foundKey.key.activated,
            expiryAmount: foundKey.key.expiryAmount || null,
            expiryUnit: foundKey.key.expiryUnit || null,
            maxDevices: foundKey.key.maxDevices || 1,
            pricePaid: finalPrice
          }
        };
      });

      return sendJSON(res, result.status, result.body);
    }

    /* ================= TRANG "NGƯỜI DÙNG" (ADMIN QUẢN LÝ TÀI KHOẢN KHÁCH HÀNG) ================= */

    /* ---- Danh sách toàn bộ tài khoản khách hàng đã đăng ký ở trang bán hàng (không trả passwordHash) ---- */
    if(pathname === '/api/admin/customers' && req.method === 'GET'){
      const list = (db.customers || []).map(c => ({
        id: c.id,
        username: c.username,
        role: c.role || 'customer',
        balance: c.balance || 0,
        createdAt: c.createdAt,
        registrationIP: c.registrationIP || null,
        topupCount: (c.topupHistory || []).length,
        transactionCount: (c.transactionHistory || []).length
      }));
      return sendJSON(res, 200, list);
    }

    /* ---- Admin cộng (hoặc trừ, nếu số âm) tiền vào tài khoản 1 khách hàng ---- */
    const topupCustomerMatch = pathname.match(/^\/api\/admin\/customers\/([a-f0-9]+)\/balance$/);
    if(topupCustomerMatch && req.method === 'POST'){
      const body = await readJSONBody(req);
      const customer = (db.customers || []).find(c => c.id === topupCustomerMatch[1]);
      if(!customer) return sendJSON(res, 404, { ok:false, error: 'not_found' });
      const amount = parseFloat(String(body.amount || '').replace(/[^\d.-]/g,'')) || 0;
      customer.balance = (customer.balance || 0) + amount;
      customer.topupHistory = customer.topupHistory || [];
      customer.topupHistory.unshift({
        id: crypto.randomBytes(8).toString('hex'),
        amount,
        method: 'admin_manual',
        status: 'approved',
        createdAt: new Date().toISOString(),
        note: String(body.note || 'Admin cộng tiền thủ công')
      });
      customer.transactionHistory = customer.transactionHistory || [];
      customer.transactionHistory.unshift({
        id: crypto.randomBytes(8).toString('hex'),
        type: amount >= 0 ? 'topup' : 'adjust',
        amount,
        balanceAfter: customer.balance,
        createdAt: new Date().toISOString(),
        note: String(body.note || 'Admin cộng tiền thủ công')
      });
      saveDBNow();
      return sendJSON(res, 200, { ok:true, customer: { id: customer.id, username: customer.username, balance: customer.balance } });
    }

    /* ---- Admin đổi mật khẩu cho 1 tài khoản khách hàng đã tạo ---- */
    const changePassCustomerMatch = pathname.match(/^\/api\/admin\/customers\/([a-f0-9]+)\/password$/);
    if(changePassCustomerMatch && req.method === 'POST'){
      const body = await readJSONBody(req);
      const customer = (db.customers || []).find(c => c.id === changePassCustomerMatch[1]);
      if(!customer) return sendJSON(res, 404, { ok:false, error: 'not_found' });
      const newPassword = String(body.newPassword || '');
      if(newPassword.length < 4){
        return sendJSON(res, 400, { ok:false, error: 'password_too_short' });
      }
      customer.passwordHash = hashPassword(newPassword);
      saveDBNow();
      return sendJSON(res, 200, { ok:true });
    }

    /* ---- Danh sách yêu cầu nạp tiền đang chờ admin duyệt ---- */
    if(pathname === '/api/admin/topup-requests' && req.method === 'GET'){
      expireStaleTopupRequests();
      return sendJSON(res, 200, db.topupRequests || []);
    }

    /* ---- Admin duyệt / từ chối 1 yêu cầu nạp tiền ---- */
    const topupDecisionMatch = pathname.match(/^\/api\/admin\/topup-requests\/([a-f0-9]+)\/(approve|reject)$/);
    if(topupDecisionMatch && req.method === 'POST'){
      expireStaleTopupRequests(); // đảm bảo không duyệt nhầm 1 request đã quá 30 phút
      const [, reqId, decision] = topupDecisionMatch;
      const reqEntry = (db.topupRequests || []).find(r => r.id === reqId);
      if(!reqEntry) return sendJSON(res, 404, { ok:false, error: 'not_found' });
      if(reqEntry.status !== 'pending') return sendJSON(res, 400, { ok:false, error: 'already_processed', status: reqEntry.status });

      // Dùng khoá theo customerId để tránh race-condition nếu admin duyệt đồng thời với
      // 1 giao dịch khác (checkout/topup khác) đang cùng sửa số dư của khách hàng này.
      await withCustomerLock(reqEntry.customerId, async ()=>{
        reqEntry.status = decision === 'approve' ? 'approved' : 'rejected';
        const customer = (db.customers || []).find(c => c.id === reqEntry.customerId);
        if(customer){
          const hist = (customer.topupHistory || []).find(h => h.id === reqEntry.id);
          if(hist) hist.status = reqEntry.status;
          if(decision === 'approve'){
            customer.balance = (customer.balance || 0) + reqEntry.amount;
            customer.transactionHistory = customer.transactionHistory || [];
            customer.transactionHistory.unshift({
              id: crypto.randomBytes(8).toString('hex'),
              type: 'topup',
              amount: reqEntry.amount,
              balanceAfter: customer.balance,
              createdAt: new Date().toISOString(),
              note: 'Nạp tiền được admin duyệt'
            });
          }
        }
      });
      saveDBNow();
      return sendJSON(res, 200, { ok:true, request: reqEntry });
    }

    /* ---- Quản lý danh sách app/tool được phép dùng server key (admin) ---- */
    if(pathname === '/api/apps' && req.method === 'GET'){
      return sendJSON(res, 200, db.apiApps || []);
    }

    const approveMatch = pathname.match(/^\/api\/apps\/([a-f0-9]+)\/approve$/);
    if(approveMatch && req.method === 'POST'){
      const app = (db.apiApps || []).find(a => a.id === approveMatch[1]);
      if(!app) return sendJSON(res, 404, { error: 'not_found' });
      app.status = 'allowed';
      saveDBDebounced();
      return sendJSON(res, 200, app);
    }

    const denyMatch = pathname.match(/^\/api\/apps\/([a-f0-9]+)\/deny$/);
    if(denyMatch && req.method === 'POST'){
      const app = (db.apiApps || []).find(a => a.id === denyMatch[1]);
      if(!app) return sendJSON(res, 404, { error: 'not_found' });
      app.status = 'denied';
      saveDBDebounced();
      return sendJSON(res, 200, app);
    }

    const removeMatch = pathname.match(/^\/api\/apps\/([a-f0-9]+)$/);
    if(removeMatch && req.method === 'DELETE'){
      db.apiApps = (db.apiApps || []).filter(a => a.id !== removeMatch[1]);
      saveDBDebounced();
      return sendJSON(res, 200, { ok: true });
    }

    return sendJSON(res, 404, { error: 'not_found' });
  }catch(e){
    console.error('[KeyVault] Lỗi xử lý request:', e);
    return sendJSON(res, 500, { error: 'server_error', message: String((e && e.message) || e) });
  }
});

/* Bắt lỗi ở tầng server (ví dụ cổng đang bị chiếm - EADDRINUSE) để in log rõ
   ràng thay vì để tiến trình thoát đột ngột không rõ nguyên nhân. */
server.on('error', (err)=>{
  console.error('[KeyVault] Lỗi server (listen):', err && err.stack ? err.stack : err);
});

/* Bind rõ '0.0.0.0' (thay vì để mặc định) để đảm bảo Render/Docker luôn nhận
   được kết nối tới cổng PORT từ bên ngoài container. */
server.listen(PORT, '0.0.0.0', ()=>{
  console.log(`✔ KeyVault server đang chạy tại http://localhost:${PORT}`);
  console.log(`  Dữ liệu được lưu tại: ${DB_FILE}`);
  console.log(`  Giao diện web: http://localhost:${PORT}/  (đã gộp chung vào index.js)`);
  console.log(`  Link xác thực API key: http://localhost:${PORT}/api/verify?key=...&app=...`);
  try{
    startAntiSleep();
  }catch(e){
    console.error('[KeyVault] Lỗi khởi động anti-sleep (bỏ qua, không ảnh hưởng server chính):', e && e.message);
  }
});

/* Chống ngủ đông (Render Free): tự ping /api/status mỗi 4 phút. Nên kết hợp thêm
   UptimeRobot/cron-job.org gọi từ bên ngoài để đánh thức chắc chắn hơn khi server đã ngủ. */
function startAntiSleep(){
  const selfUrl = process.env.RENDER_EXTERNAL_URL || process.env.SELF_URL || null;
  if(!selfUrl){
    console.log('  [Anti-sleep] Chưa xác định được địa chỉ public của server (biến RENDER_EXTERNAL_URL). Bỏ qua tự ping — vẫn nên cấu hình UptimeRobot/cron-job.org như ghi chú ở trên.');
    return;
  }
  const target = selfUrl.replace(/\/+$/, '') + '/api/status';
  console.log(`  [Anti-sleep] Sẽ tự ping ${target} mỗi 4 phút để chống ngủ đông.`);
  setInterval(()=>{
    try{
      https.get(target, (r)=>{ r.resume(); }).on('error', (e)=>{
        console.warn('[Anti-sleep] Ping thất bại (không nghiêm trọng, sẽ thử lại sau):', e.message);
      });
    }catch(e){ /* bỏ qua lỗi ping, không ảnh hưởng server chính */ }
  }, 4 * 60 * 1000);
}

// Đảm bảo ghi dữ liệu lần cuối khi tắt server bằng Ctrl+C
process.on('SIGINT', ()=>{ saveDBNow(); process.exit(0); });
process.on('SIGTERM', ()=>{ saveDBNow(); process.exit(0); });
