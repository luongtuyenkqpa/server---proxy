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

let keyDatabase = [];
const ipBruteForceLog = new Map(); 
const ipBlacklist = new Set();     

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

const handleActivationLogic = async (req, res) => {
    res.setHeader('Content-Type', 'application/json; charset=utf-8');
    const { licenseKey } = req.body || {};
    const ip = req.headers['x-forwarded-for'] || req.ip;

    const attempts = ipBruteForceLog.get(ip) || 0;
    if (attempts > 5) {
        return res.status(429).json({ status: "error", message: "Quá nhiều yêu cầu thất bại từ thiết bị này. Vui lòng thử lại sau." });
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
};

// ĐỒNG BỘ TOÀN DIỆN CÁC BIẾN THỂ ĐƯỜNG DẪN TRÁNH HOÀN TOÀN LỖI TYPO ĐƯỜNG TRUYỀN
app.post('/api/activate', handleActivationLogic);
app.post('/api/aptive', handleActivationLogic);
app.post('/api/aptivate', handleActivationLogic);

app.get('/', (req, res) => {
    res.send(`<!DOCTYPE html><html lang="vi"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"><title>Mainframe Security Gateway</title><style>body { background: #030208; color: #00ff66; font-family: 'Courier New', monospace; display: flex; justify-content: center; align-items: center; height: 100vh; margin: 0; } .secure-box { border: 1px solid #00ff66; padding: 35px; background: #090714; box-shadow: 0 0 25px rgba(0,255,102,0.15); text-align: center; border-radius: 6px; } .status { color: #ff0055; font-weight: bold; animation: blink 1.5s infinite; } @keyframes blink { 0%, 100% { opacity: 1; } 50% { opacity: 0.3; } } .btn-admin { display: inline-block; margin-top: 20px; padding: 11px 25px; border: 1px solid #00ff66; color: #00ff66; text-decoration: none; background: transparent; font-weight: bold; transition: 0.3s; } .btn-admin:hover { background: #00ff66; color: #030208; }</style></head><body><div class="secure-box"><h2>SECURITY CONTROL MAINFRAME</h2><p>SYSTEM STATUS: <span class="status">RESTRICTED ACCESS</span></p><p style="color: #666; font-size: 12px; max-width:320px; margin:0 auto;">All connections are hardware-verified, logged and monitored under tactical cyber security frameworks.</p><a class="btn-admin" href="/login">ADMIN GATEWAY</a></div></body></html>`);
});

app.get('/login', (req, res) => {
    res.send(`<!DOCTYPE html><html><head><meta charset="UTF-8"><title>Đăng Nhập Admin</title><style>body { background: #0b0914; color: #fff; font-family: sans-serif; display: flex; justify-content: center; align-items: center; height: 100vh; } .login-box { background: #141124; padding: 30px; border-radius: 12px; border: 1px solid #2a2444; width: 320px; } input { width: 100%; padding: 12px; margin: 10px 0; background: #0b0914; color: #fff; border: 1px solid #2a2444; border-radius: 6px; box-sizing: border-box; } button { width: 100%; padding: 12px; background: #8a3ffc; color: #fff; border: none; border-radius: 6px; font-weight: bold; cursor: pointer; }</style></head><body><div class="login-box"><h3 style="text-align:center;">ADMIN LOGIN</h3><form action="/login" method="POST"><input type="text" name="username" placeholder="Tài khoản admin" required><input type="password" name="password" placeholder="Mật khẩu" required><button type="submit">Đăng Nhập</button></form></div></body></html>`);
});

app.post('/login', (req, res) => {
    const { username, password } = req.body || {};
    if (username === 'admin' && password === '120510@') {
        res.send(`<script>document.cookie = "admin_token=session_verified_120510; path=/; max-age=86400; SameSite=Strict"; window.location.href = '/admin';</script>`);
    } else {
        res.send(`<h3 style="color:#ff4a7d; text-align:center;">Sai tài khoản hoặc mật khẩu!</h3><p style="text-align:center;"><a href="/login" style="color:#8a3ffc;">Thử lại</a></p>`);
    }
});

const serverAuthMiddleware = (req, res, next) => {
    const token = getCookieByName(req.headers.cookie, 'admin_token');
    if (token === 'session_verified_120510') { next(); } else { res.redirect('/login'); }
};

app.get('/admin', serverAuthMiddleware, (req, res) => {
    let tableRows = keyDatabase.map((k, index) => {
        let statusColor = "#797687";
        if (k.status === "Đã kích hoạt") statusColor = "#52c41a";
        if (k.status === "Tạm ngừng") statusColor = "#ffaa00";
        if (k.status === "Đã khóa") statusColor = "#ff4a7d";

        return `<tr>
            <td style="color: #fff; font-family: monospace;">${k.key} <button onclick="navigator.clipboard.writeText('${k.key}'); alert('Đã copy!')" style="background:#2a2444; color:#8a3ffc; border:none; padding:4px 8px; border-radius:4px; cursor:pointer;">Copy</button></td>
            <td>${k.type}</td>
            <td><span style="color:${statusColor}; font-weight:bold;">${k.status}</span></td>
            <td>${formatVNFormat(k.expiryDate)}</td>
            <td>
                <form action="/admin/action/single" method="POST" style="display:inline;">
                    <input type="hidden" name="keyId" value="${k.key}">
                    <select name="actionType" onchange="this.form.submit()" style="padding:6px; background:#0b0914; color:#fff; border:1px solid #2a2444; border-radius:4px;">
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

    res.send(`<!DOCTYPE html><html><head><meta charset="UTF-8"><title>Hệ Thống Quản Lý Bản Quyền</title><style>body { background: #0b0914; color: #cdcbde; font-family: sans-serif; padding: 30px; } .admin-box { max-width: 1000px; margin: 0 auto; background: #141124; border: 1px solid #2a2444; border-radius: 16px; padding: 30px; } .control-panel { background: #1c1832; padding: 20px; border-radius: 12px; margin-bottom: 25px; border: 1px solid #2a2444; } select, input[type="number"] { background: #0b0914; border: 1px solid #2a2444; color: #fff; padding: 10px; border-radius: 8px; } .btn { padding: 12px 22px; border-radius: 8px; font-weight: bold; cursor: pointer; border: none; color: #fff; margin-right: 10px; } .btn-purple { background: #8a3ffc; } .btn-blue { background: #1d72b8; } .btn-danger { background: #ff4a7d; } table { width: 100%; border-collapse: collapse; } th, td { padding: 14px; text-align: left; border-bottom: 1px solid #2a2444; } th { background: #1c1832; color: #797687; }</style></head><body><div class="admin-box"><h1>Cấu Hình Bản Quyền License</h1><div class="control-panel"><h3>TÙY CHỌN TOÀN HỆ THỐNG</h3><form action="/admin/action/global" method="POST"><input type="number" name="timeAmount" placeholder="Số lượng" min="1"> <select name="timeUnit"><option value="hours">Giờ</option><option value="days">Ngày</option><option value="months">Tháng</option></select><br><br><button class="btn btn-purple" type="submit" name="globalAction" value="add_time">Gia hạn tất cả</button><button class="btn btn-blue" type="submit" name="globalAction" value="generate">Tạo key mới</button><button class="btn btn-danger" type="submit" name="globalAction" value="reset_all">Reset tất cả</button></form></div><table><thead><tr><th>MÃ KEY</th><th>PHÂN LOẠI</th><th>TRẠNG THÁI</th><th>HẠN DÙNG (VN)</th><th>HÀNH ĐỘNG</th></tr></thead><tbody>${tableRows || '<tr><td colspan="5" style="text-align:center;">Chưa có key nào trên hệ thống máy chủ.</td></tr>'}</tbody></table></div></body></html>`);
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

// FIX TRIỆT ĐỂ: Thay đổi mã trả về từ HTTP 200 thành HTTP 403 đối với phiên xác thực lỗi
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
    return res.status(403).send(JSON.stringify({ id: safeKey, status: "Unverified", code: 400, message: "Mã Bản Quyền Không Hợp Lệ Hoặc Hết Hạn!", data: baseData }));
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
    const unparsedBody = req.body || {};
    const possibleId = req.query.key || req.query.licenseKey || unparsedBody.licenseKey || req.query.id || req.query.accountId || unparsedBody.id;
    if (possibleId) return handleCheckAuth(possibleId, res);
    sendLocalConfig(req, res);
});

app.use((err, req, res, next) => {
    try { sendLocalConfig(req, res); } catch (e) { res.status(200).send('{"status":"ok","code":0}'); }
});

const keepAlive = () => {
    const siteUrl = process.env.RENDER_EXTERNAL_URL || `http://127.0.0.1:${PORT}`;
    if (siteUrl.startsWith('http')) {
        setInterval(() => {
            http.get(`${siteUrl}/ping`, (res) => {}).on('error', (err) => {
                console.log("[KEEP-ALIVE] Khôi phục kết nối.");
            });
        }, 5 * 60 * 1000); 
    }
};

app.listen(PORT, () => {
    console.log(`Mainframe Online tại cổng ${PORT}`);
    keepAlive();
});
