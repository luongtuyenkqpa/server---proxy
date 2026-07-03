const express = require('express');
const app = express(); 
const http = require('http');
const PORT = process.env.PORT || 3000;

// ==========================================
// THIẾT LẬP MÔI TRƯỜNG CHUYÊN NGHIỆP
// ==========================================
app.disable('x-powered-by'); 
app.set('trust proxy', 1);   

app.use((req, res, next) => {
    res.header("Access-Control-Allow-Origin", "*");
    res.header("Access-Control-Allow-Methods", "GET, POST, OPTIONS, PUT, PATCH, DELETE");
    res.header("Access-Control-Allow-Headers", "Origin, X-Requested-With, Content-Type, Accept, Authorization, X-Unity-Version, User-Agent");
    res.header("Cache-Control", "no-store, no-cache, must-revalidate, proxy-revalidate");
    
    if (req.method === 'OPTIONS') {
        return res.sendStatus(200);
    }
    next();
});

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Cơ sở dữ liệu và bộ nhớ đệm lưu trữ lớp phòng thủ
let keyDatabase = [];
const ipBruteForceLog = new Map(); 
const ipBlacklist = new Set();     

// Hệ thống tự động giải phóng bộ nhớ RAM định kỳ sau mỗi 15 phút
setInterval(() => {
    ipBruteForceLog.clear();
    console.log(`[SYSTEM] Lịch trình tự động: Đã làm sạch bộ nhớ đệm chống brute-force.`);
}, 15 * 60 * 1000);

// =========================================================================
// HỆ THỐNG TƯỜNG LỬA BẢO MẬT QUÂN SỰ VÀ PHÒNG THỦ CẤP CAO
// =========================================================================
const militaryFirewall = (req, res, next) => {
    const ip = req.headers['x-forwarded-for'] || req.ip || req.socket.remoteAddress;
    
    if (ipBlacklist.has(ip)) {
        return res.status(403).json({ status: "cyber_defense", message: "Access denied by automated military-grade firewall security." });
    }

    const maliciousPattern = /(\.\.\/|select\s+.*\s+from|union\s+select|<script>|'|--|sqlmap|dirbuster|nikto)/i;
    if (maliciousPattern.test(req.url) || maliciousPattern.test(JSON.stringify(req.body))) {
        ipBlacklist.add(ip); 
        console.warn(`[FIREWALL BAN] Phát hiện hành vi dò quét thù địch từ IP: ${ip}`);
        return res.status(400).json({ error: "Malicious payload signature detected. IP permanently blocked." });
    }
    next();
};
app.use(militaryFirewall);

function getVNTime(offsetHours = 0, baseDate = null) {
    const current = baseDate ? new Date(baseDate) : new Date();
    if (offsetHours !== 0) {
        current.setTime(current.getTime() + (offsetHours * 60000 * 60));
    }
    return current;
}

function formatVNFormat(dateObj) {
    if (!dateObj) return "Chưa kích hoạt";
    try {
        const formatter = new Intl.DateTimeFormat('vi-VN', {
            timeZone: 'Asia/Ho_Chi_Minh',
            year: 'numeric', month: '2-digit', day: '2-digit',
            hour: '2-digit', minute: '2-digit', second: '2-digit',
            hour12: false
        });
        return formatter.format(new Date(dateObj)).replace(/, /g, ' ');
    } catch (e) {
        const pad = (n) => n.toString().padStart(2, '0');
        const d = new Date(dateObj);
        return `${pad(d.getDate())}/${pad(d.getMonth() + 1)}/${d.getFullYear()} ${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`;
    }
}

function getCookieByName(cookieHeader, name) {
    if (!cookieHeader) return null;
    const matches = cookieHeader.match(new RegExp('(?:^|; )' + name.replace(/([\.$?*|{}\(\)\[\]\\\/\+^])/g, '\\$1') + '=([^;]*)'));
    return matches ? decodeURIComponent(matches[1]) : null;
}

const sanitizeInput = (input) => {
    if (!input) return null;
    return Array.isArray(input) ? String(input[0]).trim() : String(input).trim();
};

const sendLocalConfig = (req, res) => {
    if (res.headersSent) return;
    res.setHeader('Content-Type', 'application/json; charset=utf-8');
    res.setHeader('Connection', 'keep-alive');
    res.setHeader('X-Content-Type-Options', 'nosniff');

    const optimizedResponse = {
        "status": "ok",
        "code": 0,
        "message": "success",
        "maintenance": false,
        "server_status": "online",
        "region": "VN",
        "version": "1.105.1",
        "verAddr": "https://server-proxy-woad.vercel.app/",
        "resetGuest": true,
        "p_version": "1.105.1",
        "patch_url": "",
        "file_size": 0,
        "is_mandatory": false,
        "update_type": "none",
        "data": { "is_white": true, "login_open": true, "server_time": Math.floor(Date.now() / 1000), "cdn_url": "", "patch_version": "1.105.1" },
        "extension": { "cdn_backup": "https://server-proxy-woad.vercel.app/", "retry_count": 0, "maintenance_mode": false }
    };
    res.status(200).send(JSON.stringify(optimizedResponse));
};

// ==========================================
// CỔNG KẾT NỐI API BẢO MẬT CHO ỨNG DỤNG ĐIỆN THOẠI
// ==========================================
app.post('/api/activate', async (req, res) => {
    res.setHeader('Content-Type', 'application/json; charset=utf-8');
    const { licenseKey } = req.body || {};
    const ip = req.headers['x-forwarded-for'] || req.ip;

    const attempts = ipBruteForceLog.get(ip) || 0;
    if (attempts > 5) {
        return res.status(429).json({ status: "error", message: "Quá nhiều yêu cầu thất bại từ thiết bị này. Khóa truy cập tạm thời." });
    }

    if (!licenseKey) {
        return res.status(400).json({ status: "error", message: "Vui lòng nhập đầy đủ mã License Key." });
    }

    const safeKey = String(licenseKey).trim();
    const now = getVNTime();

    let targetRecord = keyDatabase.find(k => k.key === safeKey);

    if (!targetRecord) {
        ipBruteForceLog.set(ip, attempts + 1);
        await new Promise(resolve => setTimeout(resolve, 300 + Math.random() * 200));
        return res.status(404).json({ status: "error", message: "Mã key license không tồn tại trên hệ thống." });
    }

    ipBruteForceLog.delete(ip);

    if (targetRecord.status === "Đã khóa") {
        return res.status(403).json({ status: "error", message: "Mã key này đã bị khóa vĩnh viễn." });
    }
    if (targetRecord.status === "Tạm ngừng") {
        return res.status(403).json({ status: "error", message: "Key đang bảo trì bởi quản trị viên." });
    }
    if (targetRecord.expiryDate && now >= new Date(targetRecord.expiryDate)) {
        return res.status(403).json({ status: "error", message: "Mã bản quyền này đã hết hạn sử dụng." });
    }

    let expiryVN = targetRecord.expiryDate ? new Date(targetRecord.expiryDate) : getVNTime(targetRecord.durationHours);
    targetRecord.expiryDate = expiryVN;
    targetRecord.status = "Đã kích hoạt";

    return res.status(200).json({
        status: "success",
        message: "Xác thực bản quyền thành công!",
        expiry: formatVNFormat(expiryVN)
    });
});

// CỔNG GIÁM SÁT AN NINH SANG TRỌNG CAO CẤP CHUYÊN NGHIỆP
app.get('/', (req, res) => {
    res.send(`<!DOCTYPE html><html lang="vi"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"><title>Licensing Mainframe Gateway</title><style>body { background: #09090e; color: #a4a4ca; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; display: flex; justify-content: center; align-items: center; height: 100vh; margin: 0; } .secure-panel { border: 1px solid #1f1f2e; padding: 45px 35px; background: #11111a; box-shadow: 0 12px 40px rgba(0,0,0,0.6); text-align: center; border-radius: 12px; max-width: 400px; } h2 { color: #ffffff; font-weight: 600; font-size: 20px; margin-top: 0; letter-spacing: 0.5px; } .badge { display: inline-block; padding: 4px 12px; background: rgba(0, 255, 102, 0.1); color: #00ff66; font-size: 11px; font-weight: bold; border-radius: 20px; letter-spacing: 1px; margin-bottom: 15px; } .desc { font-size: 13px; color: #6d6d8a; line-height: 1.6; margin-bottom: 25px; } .btn-admin { display: block; padding: 12px; background: #5a32a8; color: #fff; text-decoration: none; font-weight: bold; font-size: 14px; border-radius: 8px; transition: background 0.2s, transform 0.1s; } .btn-admin:hover { background: #6f42c1; } .btn-admin:active { transform: scale(0.98); }</style></head><body><div class="secure-panel"><div class="badge">● GATEWAY SECURED</div><h2>CENTRAL AUTH MAINFRAME</h2><p class="desc">Hệ thống xử lý và chứng thực phân phối mã khóa bản quyền SaaS độc lập. Mọi phiên kết nối được bảo vệ bởi lớp tường lửa mã hóa phần cứng toàn vẹn.</p><a class="btn-admin" href="/login">Khu vực quản trị</a></div></body></html>`);
});

app.get('/login', (req, res) => {
    res.send(`<!DOCTYPE html><html><head><meta charset="UTF-8"><title>Đăng Nhập Quản Trị</title><style>body { background: #09090e; color: #fff; font-family: sans-serif; display: flex; justify-content: center; align-items: center; height: 100vh; margin: 0; } .login-box { background: #11111a; padding: 40px 30px; border-radius: 12px; border: 1px solid #1f1f2e; width: 340px; box-shadow: 0 10px 30px rgba(0,0,0,0.5); box-sizing: border-box; } h3 { text-align: center; margin-top:0; font-weight: 600; color: #fff; letter-spacing: 0.5px; } input { width: 100%; padding: 12px; margin: 10px 0; background: #050508; color: #fff; border: 1px solid #1f1f2e; border-radius: 6px; box-sizing: border-box; font-size: 14px; transition: border 0.2s; } input:focus { border-color: #5a32a8; outline: none; } button { width: 100%; padding: 13px; background: #5a32a8; color: #fff; border: none; border-radius: 6px; font-weight: bold; font-size: 14px; cursor: pointer; transition: background 0.2s; margin-top: 10px; } button:hover { background: #6f42c1; }</style></head><body><div class="login-box"><h3>ADMIN MAINFRAME</h3><form action="/login" method="POST"><input type="text" name="username" placeholder="Tài khoản hệ thống" required><input type="password" name="password" placeholder="Mật khẩu mã hóa" required><button type="submit">Đăng Nhập Khóa</button></form></div></body></html>`);
});

app.post('/login', (req, res) => {
    const { username, password } = req.body || {};
    if (username === 'admin' && password === '120510@') {
        res.send(`<script>document.cookie = "admin_token=session_verified_120510; path=/; max-age=86400; SameSite=Strict"; window.location.href = '/admin';</script>`);
    } else {
        res.send(`<body style="background:#09090e; color:#ff4a7d; font-family:sans-serif; text-align:center; padding-top:50px;"><h3>Thông tin xác thực sai hoặc không có quyền!</h3><p><a href="/login" style="color:#5a32a8; font-weight:bold; text-decoration:none;">Thử lại</a></p>body>`);
    }
});

const serverAuthMiddleware = (req, res, next) => {
    const token = getCookieByName(req.headers.cookie, 'admin_token');
    if (token === 'session_verified_120510') { next(); } else { res.redirect('/login'); }
};

// GIAO DIỆN TRANG QUẢN TRỊ PROFESSIONAL TRỰC QUAN CAO CẤP
app.get('/admin', serverAuthMiddleware, (req, res) => {
    // Tính toán chỉ số thống kê
    const totalKeys = keyDatabase.length;
    const activeKeys = keyDatabase.filter(k => k.status === "Đã kích hoạt").length;
    const bannedKeys = keyDatabase.filter(k => k.status === "Đã khóa").length;

    let tableRows = keyDatabase.map((k, index) => {
        let badgeStyle = "background: rgba(121, 118, 135, 0.1); color: #797687;";
        if (k.status === "Đã kích hoạt") badgeStyle = "background: rgba(82, 196, 26, 0.1); color: #52c41a;";
        if (k.status === "Tạm ngừng") badgeStyle = "background: rgba(255, 170, 0, 0.1); color: #ffaa00;";
        if (k.status === "Đã khóa") badgeStyle = "background: rgba(255, 74, 125, 0.1); color: #ff4a7d;";

        return `<tr>
            <td style="color: #fff; font-family: monospace; font-size: 14px; font-weight: 500;">
                ${k.key} 
                <button onclick="navigator.clipboard.writeText('${k.key}'); alert('Đã sao chép mã khóa!')" style="background:#1f1f2e; color:#a4a4ca; border:none; padding:3px 8px; border-radius:4px; cursor:pointer; font-size:11px; margin-left:5px;">Copy</button>
            </td>
            <td><span style="font-size: 13px;">${k.type}</span></td>
            <td><span style="padding: 4px 10px; border-radius: 12px; font-size: 12px; font-weight: bold; ${badgeStyle}">${k.status}</span></td>
            <td style="color: #a4a4ca; font-size: 13px;">${formatVNFormat(k.expiryDate)}</td>
            <td>
                <form action="/admin/action/single" method="POST" style="display:inline;">
                    <input type="hidden" name="keyId" value="${k.key}">
                    <select name="actionType" onchange="this.form.submit()" style="padding:6px 10px; background:#050508; color:#fff; border:1px solid #1f1f2e; border-radius:6px; font-size:12px; cursor:pointer;">
                        <option value="">Thao tác...</option>
                        <option value="add_1h">+1 Giờ</option>
                        <option value="add_1d">+1 Ngày</option>
                        <option value="add_1m">+1 Tháng</option>
                        <option value="pause">Tạm Ngừng</option>
                        <option value="resume">Bỏ Tạm Ngừng</option>
                        <option value="reset">Reset Key</option>
                        <option value="band">Khóa Key</option>
                        <option value="unband">Mở Khóa</option>
                        <option value="delete">Xóa Key</option>
                    </select>
                </form>
            </td>
        </tr>`;
    }).join('');

    res.send(`<!DOCTYPE html><html><head><meta charset="UTF-8"><title>Bảng Điều Khiển Giấy Phép SaaS</title><style>body { background: #09090e; color: #a4a4ca; font-family: -apple-system, BlinkMacSystemFont, sans-serif; padding: 30px; margin: 0; } .admin-box { max-width: 1050px; margin: 0 auto; background: #11111a; border: 1px solid #1f1f2e; border-radius: 12px; padding: 35px; box-shadow: 0 15px 50px rgba(0,0,0,0.5); } h1 { color: #fff; font-size: 22px; margin-top: 0; font-weight: 600; } .stats-bar { display: flex; gap: 20px; margin-bottom: 30px; } .stat-card { flex: 1; background: #161622; border: 1px solid #1f1f2e; padding: 15px 20px; border-radius: 8px; } .stat-card span { font-size: 12px; color: #6d6d8a; text-transform: uppercase; letter-spacing: 0.5px; } .stat-card div { font-size: 24px; color: #fff; font-weight: bold; margin-top: 5px; } .control-panel { background: #161622; padding: 25px; border-radius: 8px; margin-bottom: 30px; border: 1px solid #1f1f2e; } select, input[type="number"] { background: #050508; border: 1px solid #1f1f2e; color: #fff; padding: 10px 14px; border-radius: 6px; font-size: 13px; } .btn { padding: 11px 20px; border-radius: 6px; font-weight: bold; font-size: 13px; cursor: pointer; border: none; color: #fff; margin-right: 10px; transition: opacity 0.2s; } .btn:hover { opacity: 0.9; } .btn-purple { background: #5a32a8; } .btn-blue { background: #1d72b8; } .btn-danger { background: #ff4a7d; } table { width: 100%; border-collapse: collapse; margin-top: 10px; } th, td { padding: 15px; text-align: left; border-bottom: 1px solid #1f1f2e; } th { background: #161622; color: #6d6d8a; font-size: 12px; text-transform: uppercase; letter-spacing: 0.5px; font-weight: 600; }</style></head><body><div class="admin-box"><h1>Giám Sát Cấu Hình Bản Quyền</h1><div class="stats-bar"><div class="stat-card"><span>Tổng Giấy Phép</span><div>${totalKeys}</div></div><div class="stat-card"><span>Đang Hoạt Động</span><div style="color: #52c41a;">${activeKeys}</div></div><div class="stat-card"><span>Bị Khóa Đóng Băng</span><div style="color: #ff4a7d;">${bannedKeys}</div></div></div><div class="control-panel"><form action="/admin/action/global" method="POST"><input type="number" name="timeAmount" placeholder="Số lượng lượng lớn" min="1"> <select name="timeUnit"><option value="hours">Giờ</option><option value="days">Ngày</option><option value="months">Tháng</option></select> <button class="btn btn-purple" type="submit" name="globalAction" value="add_time">Gia hạn hàng loạt</button><button class="btn btn-blue" type="submit" name="globalAction" value="generate">Khởi tạo mã key mới</button><button class="btn btn-danger" type="submit" name="globalAction" value="reset_all">Làm mới trạng thái tất cả</button></form></div><table><thead><tr><th>MÃ BẢN QUYỀN TRUY CẬP</th><th>HẠNG MỤC PHÂN LOẠI</th><th>TRẠNG THÁI</th><th>THỜI HẠN SỬ DỤNG (VN)</th><th>BẢO TRÌ ĐƠN LẺ</th></tr></thead><tbody>${tableRows || '<tr><td colspan="5" style="text-align:center; color:#6d6d8a; padding: 30px 0;">Không tìm thấy cấu trúc giấy phép hiện hành trên phân vùng nhớ máy chủ.</td></tr>'}</tbody></table></div></body></html>`);
});

app.post('/admin/action/single', serverAuthMiddleware, (req, res) => {
    try {
        const { keyId, actionType } = req.body || {};
        if (!keyId) return res.redirect('/admin');
        let item = keyDatabase.find(k => k.key === keyId.trim());
        if (!item) return res.redirect('/admin');

        switch(actionType) {
            case "add_1h": if (item.expiryDate) item.expiryDate = getVNTime(1, item.expiryDate); break;
            case "add_1d": if (item.expiryDate) item.expiryDate = getVNTime(24, item.expiryDate); break;
            case "add_1m": if (item.expiryDate) item.expiryDate = getVNTime(24 * 30, item.expiryDate); break;
            case "pause": if (item.status === "Đã kích hoạt") item.status = "Tạm ngừng"; break;
            case "resume": if (item.status === "Tạm ngừng") item.status = "Đã kích hoạt"; break;
            case "reset": item.status = "Chưa kích hoạt"; item.expiryDate = null; break; 
            case "band": item.status = "Đã khóa"; break;
            case "unband": if (item.status === "Đã khóa") item.status = "Chưa kích hoạt"; break;
            case "delete": keyDatabase = keyDatabase.filter(k => k.key !== keyId.trim()); break;
        }
    } catch (err) { console.error(err); }
    res.redirect('/admin');
});

app.post('/admin/action/global', serverAuthMiddleware, (req, res) => {
    try {
        const { globalAction, timeAmount, timeUnit } = req.body || {};
        if (globalAction === "generate") {
            const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
            const segment = () => Array.from({length: 4}, () => chars[Math.floor(Math.random() * chars.length)]).join('');
            keyDatabase.unshift({ key: `${segment()}-${segment()}-${segment()}`, type: "Gói Cao Cấp", durationHours: 24, status: "Chưa kích hoạt", expiryDate: null }); 
        } else if (globalAction === "add_time") {
            let amount = parseInt(timeAmount);
            if (!isNaN(amount) && amount > 0) {
                let hoursValue = timeUnit === "days" ? amount * 24 : timeUnit === "months" ? amount * 24 * 30 : amount;
                keyDatabase.forEach(k => { if (k.expiryDate) k.expiryDate = getVNTime(hoursValue, k.expiryDate); });
            }
        } else if (globalAction === "reset_all") {
            keyDatabase.forEach(k => { k.status = "Chưa kích hoạt"; k.expiryDate = null; });
        }
    } catch (err) { console.error(err); }
    res.redirect('/admin');
});

// HÀM XÁC THỰC AUTH DỰA TRÊN LICENSE KEY ĐỘC LẬP TRÊN THIẾT BỊ
function handleCheckAuth(licenseId, res) {
    const safeKey = sanitizeInput(licenseId);
    if (!safeKey) return res.status(400).json({ status: "error", message: "Invalid Key Parameter" });
    
    const clientRecord = keyDatabase.find(k => k.key === safeKey);
    const now = getVNTime();
    const baseData = { is_white: true, login_open: true, server_time: Math.floor(Date.now() / 1000), cdn_url: "", patch_version: "1.105.1" };

    if (clientRecord && clientRecord.status === "Đã kích hoạt" && clientRecord.expiryDate && now < new Date(clientRecord.expiryDate)) {
        return res.status(200).send(JSON.stringify({ 
            id: safeKey, 
            status: "Verified", 
            code: 0, 
            message: "Xác thực giấy phép thành công.", 
            remaining_seconds: Math.floor((new Date(clientRecord.expiryDate) - now) / 1000), 
            data: baseData 
        }));
    }
    return res.status(200).send(JSON.stringify({ id: safeKey, status: "Unverified", code: 400, message: "Mã Bản Quyền Không Hợp Lệ Hoặc Hết Hạn!", data: baseData }));
}

app.get('/check-auth', (req, res) => { handleCheckAuth(req.query.id || req.query.key, res); });
app.get('/ping', (req, res) => res.send('Heartbeat active'));

app.all('*', (req, res) => {
    if (req.path === '/favicon.ico') return res.status(204).end();
    const ext = req.path.split('.').pop().toLowerCase();
    const binaryExts = ['bundle', 'unity3d', 'apk', 'obb', 'png', 'jpg', 'jpeg', 'zip', 'bin', 'hash', 'dat', 'manifest'];
    if (req.path.includes('.') && binaryExts.includes(ext)) {
        res.setHeader('Content-Type', 'application/octet-stream');
        res.setHeader('Content-Length', '0');
        return res.status(200).end();
    }
    if (req.path.includes('.')) return sendLocalConfig(req, res);
    
    // Quét sạch tất cả các tham số truyền lên từ Client để tìm License Key ứng dụng
    const unparsedBody = req.body || {};
    const possibleKey = req.query.key || req.query.licenseKey || unparsedBody.licenseKey || req.query.id || unparsedBody.id;
    if (possibleKey) return handleCheckAuth(possibleKey, res);
    sendLocalConfig(req, res);
});

app.use((err, req, res, next) => {
    try { sendLocalConfig(req, res); } catch (e) { res.status(200).send('{"status":"ok","code":0}'); }
});

app.listen(PORT, () => console.log(`Mainframe Online tại cổng ${PORT}`));
