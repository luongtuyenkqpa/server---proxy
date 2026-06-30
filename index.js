const express = require('express');
const app = express(); 
const http = require('http');
const PORT = process.env.PORT || 3000;

// ==========================================
// THIẾT LẬP MÔI TRƯỜNG CHUYÊN NGHIỆP
// ==========================================
app.disable('x-powered-by'); // Ẩn danh tính Express Server
app.set('trust proxy', 1);   // Xác thực IP thật qua Cloudflare / Vercel

// Cấu hình CORS & Middleware
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

// Hàm làm sạch ID, ngăn chặn mảng hóa (Array Spoofing)
const sanitizeInput = (input) => {
    if (!input) return null;
    return Array.isArray(input) ? String(input[0]).trim() : String(input).trim();
};

// ==========================================
// TÀI NGUYÊN CẤU HÌNH CHO GAME
// ==========================================
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
        "data": {
            "is_white": true,
            "login_open": true,
            "server_time": Math.floor(Date.now() / 1000),
            "cdn_url": "",
            "patch_version": "1.105.1"
        },
        "extension": {
            "cdn_backup": "https://server-proxy-woad.vercel.app/",
            "retry_count": 0,
            "maintenance_mode": false
        }
    };

    const body = JSON.stringify(optimizedResponse);
    res.setHeader('Content-Length', Buffer.byteLength(body, 'utf-8'));
    res.status(200).send(body);
};

const renderNotificationPage = (title, message, isSuccess = false, type = "error") => {
    let color = "#ff4a7d"; 
    let borderColor = "#ff4a7d";
    if (isSuccess) { color = "#52c41a"; borderColor = "#52c41a"; }
    else if (type === "warning") { color = "#ffaa00"; borderColor = "#ffaa00"; }

    return `
    <!DOCTYPE html>
    <html lang="vi">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>${title}</title>
        <style>
            body { background: #0b0914; color: #fff; font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; display: flex; justify-content: center; align-items: center; height: 100vh; margin: 0; }
            .card { background: #141124; padding: 40px 30px; border-radius: 16px; border: 1px solid ${borderColor}; width: 380px; box-shadow: 0 8px 32px rgba(0,0,0,0.6); text-align: center; box-sizing: border-box; }
            h2 { color: ${color}; margin-top: 0; font-size: 22px; letter-spacing: 0.5px; }
            p { color: #cdcbde; font-size: 15px; line-height: 1.6; margin: 20px 0; }
            .btn-back { display: inline-block; width: 100%; padding: 12px; background: #2a2444; border: 1px solid #3d3566; color: #fff; font-size: 14px; font-weight: bold; border-radius: 8px; text-decoration: none; transition: all 0.2s; box-sizing: border-box; }
            .btn-back:hover { background: #8a3ffc; border-color: #8a3ffc; }
        </style>
    </head>
    <body>
        <div class="card">
            <h2>${title}</h2>
            <p>${message}</p>
            <a class="btn-back" href="/">QUAY LẠI TRANG CHỦ</a>
        </div>
    </body>
    </html>`;
};

app.get('/', (req, res) => {
    res.send(`
    <!DOCTYPE html>
    <html lang="vi">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Hệ Thống Xác Thực Bản Quyền</title>
        <style>
            body { background: #0b0914; color: #fff; font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; display: flex; justify-content: center; align-items: center; height: 100vh; margin: 0; position: relative; overflow: hidden; }
            .menu-trigger { position: absolute; top: 20px; left: 20px; width: 30px; height: 20px; display: flex; flex-direction: column; justify-content: space-between; cursor: pointer; z-index: 10; }
            .menu-trigger div { height: 3px; background-color: #fff; border-radius: 2px; transition: 0.3s; }
            .side-menu { position: absolute; top: 0; left: -250px; width: 250px; height: 100%; background: #141124; border-right: 1px solid #2a2444; transition: 0.3s; padding: 60px 20px 20px 20px; box-sizing: border-box; }
            .side-menu.active { left: 0; }
            .side-menu a { display: block; color: #cdcbde; text-decoration: none; padding: 12px; margin-bottom: 10px; border-radius: 6px; background: #1c1832; font-size: 14px; text-align: center; }
            .side-menu a:hover { background: #8a3ffc; color: #fff; }
            .activation-box { background: #141124; padding: 35px; border-radius: 16px; border: 1px solid #2a2444; width: 380px; box-shadow: 0 8px 32px rgba(0,0,0,0.5); }
            h2 { color: #fff; margin: 0 0 10px 0; font-size: 22px; text-align: center; }
            .notice { background: rgba(138, 63, 252, 0.1); border: 1px solid #8a3ffc; padding: 12px; border-radius: 8px; font-size: 13px; color: #cdcbde; margin-bottom: 20px; line-height: 1.5; text-align: center; }
            label { display: block; font-size: 13px; color: #797687; margin-bottom: 6px; font-weight: 500; }
            input { width: 100%; padding: 12px; margin-bottom: 15px; border-radius: 8px; border: 1px solid #2a2444; background: #0b0914; color: #fff; box-sizing: border-box; font-size: 14px; }
            input:focus { border-color: #8a3ffc; outline: none; }
            .btn-submit { width: 100%; padding: 14px; background: #8a3ffc; border: none; color: #fff; font-size: 15px; font-weight: bold; border-radius: 8px; cursor: pointer; transition: background 0.2s; }
            .btn-submit:hover { background: #6928c8; }
        </style>
    </head>
    <body>
        <div class="menu-trigger" onclick="toggleMenu()">
            <div></div><div></div><div></div>
        </div>
        <div class="side-menu" id="sideMenu">
            <a href="/admin">Đăng Nhập Quản Trị</a>
        </div>
        <div class="activation-box">
            <h2>Kích Hoạt Bản Quyền</h2>
            <div class="notice">Vui lòng kích hoạt key và nhập ID Game để xác thực trạng thái tài khoản trên hệ thống máy chủ.</div>
            <form action="/activate" method="POST">
                <label>ID GAME</label>
                <input type="text" name="idGame" placeholder="Nhập ID Game của bạn" required>
                <label>MÃ KEY LICENSE</label>
                <input type="text" name="licenseKey" placeholder="64KA-XXXX-XXXX-XXXX" required>
                <button class="btn-submit" type="submit">KÍCH HOẠT NGAY</button>
            </form>
        </div>
        <script>
            function toggleMenu() {
                document.getElementById('sideMenu').classList.toggle('active');
            }
        </script>
    </body>
    </html>
    `);
});

app.post('/activate', (req, res) => {
    try {
        // Dự phòng req.body bị undefined (Phòng lỗi 500)
        const { idGame, licenseKey } = req.body || {};
        
        if (!licenseKey || typeof licenseKey !== 'string' || !idGame || typeof idGame !== 'string') {
            return res.send(renderNotificationPage("DỮ LIỆU KHÔNG HỢP LỆ", "Vui lòng điền đầy đủ ID Game và Mã Key hợp lệ.", false, "error"));
        }

        const safeKey = licenseKey.trim();
        const safeId = idGame.trim();

        let targetRecord = keyDatabase.find(k => k.key === safeKey);
        const now = getVNTime();

        if (!targetRecord) {
            return res.send(renderNotificationPage("LỖI XÁC THỰC", "Mã key license vừa nhập không tồn tại hoặc đã bị xóa khỏi hệ thống máy chủ.", false, "error"));
        }
        if (targetRecord.status === "Đã khóa") {
            return res.send(renderNotificationPage("KEY BỊ KHÓA", "Mã key này đã bị vô hiệu hóa hoặc khóa (Banned) vĩnh viễn do vi phạm điều khoản.", false, "error"));
        }
        if (targetRecord.status === "Tạm ngừng") {
            return res.send(renderNotificationPage("TẠM NGỪNG HOẠT ĐỘNG", "Mã key đang trong trạng thái tạm ngừng bảo trì bởi quản trị viên hệ thống.", false, "warning"));
        }
        if (targetRecord.expiryDate && now >= new Date(targetRecord.expiryDate)) {
            return res.send(renderNotificationPage("KEY HẾT HẠN", "Thời gian sử dụng của mã bản quyền này đã kết thúc. Vui lòng gia hạn thêm.", false, "error"));
        }
        if (targetRecord.status === "Đã kích hoạt" && targetRecord.idGame !== safeId) {
            return res.send(renderNotificationPage("SAI ĐỊA CHỈ ID", "Mã key này trước đó đã được liên kết cố định với một ID tài khoản Game khác.", false, "error"));
        }

        const startVN = getVNTime();
        let expiryVN = targetRecord.expiryDate ? new Date(targetRecord.expiryDate) : getVNTime(targetRecord.durationHours);
        targetRecord.expiryDate = expiryVN;

        targetRecord.status = "Đã kích hoạt";
        targetRecord.idGame = safeId;

        res.send(`
        <!DOCTYPE html>
        <html lang="vi">
        <head>
            <meta charset="UTF-8">
            <title>Xác Thực Thành Công</title>
            <style>
                body { background: #0b0914; color: #fff; font-family: 'Segoe UI', sans-serif; display: flex; justify-content: center; align-items: center; height: 100vh; margin: 0; }
                .card { background: #141124; padding: 30px; border-radius: 16px; border: 1px solid #52c41a; width: 400px; box-shadow: 0 8px 32px rgba(0,0,0,0.6); }
                h2 { color: #52c41a; text-align: center; margin-top: 0; letter-spacing: 1px; font-size: 20px; }
                .row { background: #0b0914; padding: 14px; margin: 12px 0; border-radius: 8px; font-size: 14px; border-left: 4px solid #8a3ffc; display: flex; justify-content: space-between; align-items: center; }
                .val { font-weight: bold; color: #00e5ff; font-family: monospace; }
                .btn-home { display: block; text-align: center; margin-top: 25px; color: #8a3ffc; text-decoration: none; font-size: 14px; font-weight: bold; }
                .btn-home:hover { color: #fff; }
            </style>
        </head>
        <body>
            <div class="card">
                <h2>KÍCH HOẠT THÀNH CÔNG</h2>
                <div class="row"><span>ID Game:</span> <span class="val">${safeId}</span></div>
                <div class="row"><span>Thời gian bắt đầu:</span> <span class="val">${formatVNFormat(startVN)}</span></div>
                <div class="row"><span>Thời gian hết hạn:</span> <span class="val">${formatVNFormat(expiryVN)}</span></div>
                <a class="btn-home" href="/">Quay lại trang chủ</a>
            </div>
        </body>
        </html>
        `);
    } catch (err) {
        sendLocalConfig(req, res);
    }
});

app.get('/login', (req, res) => {
    res.send(`
    <!DOCTYPE html>
    <html lang="vi">
    <head>
        <meta charset="UTF-8">
        <title>Đăng Nhập Quản Trị</title>
        <style>
            body { background: #0b0914; color: #fff; font-family: sans-serif; display: flex; justify-content: center; align-items: center; height: 100vh; margin: 0; }
            .login-box { background: #141124; padding: 30px; border-radius: 12px; border: 1px solid #2a2444; width: 320px; box-shadow: 0 4px 24px rgba(0,0,0,0.5); }
            input { width: 100%; padding: 12px; margin: 10px 0; border-radius: 6px; border: 1px solid #2a2444; background: #0b0914; color: #fff; box-sizing: border-box; }
            button { width: 100%; padding: 12px; background: #8a3ffc; border: none; color: #fff; font-weight: bold; border-radius: 6px; cursor: pointer; }
        </style>
    </head>
    <body>
        <div class="login-box">
            <h3 style="text-align:center; margin-top:0; letter-spacing:1px;">ADMIN LOGIN</h3>
            <form action="/login" method="POST">
                <input type="text" name="username" placeholder="Tài khoản admin" required>
                <input type="password" name="password" placeholder="Mật khẩu" required>
                <button type="submit">Đăng Nhập</button>
            </form>
        </div>
    </body>
    </html>
    `);
});

app.post('/login', (req, res) => {
    const { username, password } = req.body || {};
    if (username === 'admin' && password === '120510@') {
        res.send(`
            <script>
                document.cookie = "admin_token=session_verified_120510; path=/; max-age=86400; SameSite=Strict";
                window.location.href = '/admin';
            </script>
        `);
    } else {
        res.send(`<h3 style="color:#ff4a7d; text-align:center; font-family:sans-serif; margin-top:50px;">Sai tài khoản hoặc mật khẩu!</h3><p style="text-align:center;"><a href="/login" style="color:#8a3ffc;">Thử lại</a></p>`);
    }
});

const serverAuthMiddleware = (req, res, next) => {
    const token = getCookieByName(req.headers.cookie, 'admin_token');
    if (token === 'session_verified_120510') {
        next();
    } else {
        res.redirect('/login');
    }
};

app.get('/admin', serverAuthMiddleware, (req, res) => {
    let tableRows = keyDatabase.map((k, index) => {
        let statusColor = "#1890ff";
        if (k.status === "Chưa kích hoạt") statusColor = "#797687";
        if (k.status === "Đã kích hoạt") statusColor = "#52c41a";
        if (k.status === "Tạm ngừng") statusColor = "#ffaa00";
        if (k.status === "Đã khóa") statusColor = "#ff4a7d";

        return `
        <tr>
            <td style="color: #fff; font-family: monospace;">
                <span id="key-${index}">${k.key}</span>
                <button onclick="copyToClipboard('${k.key}')" style="margin-left: 8px; background: #2a2444; border: 1px solid #3d3566; color: #8a3ffc; padding: 4px 10px; border-radius: 4px; font-size: 11px; cursor: pointer; transition: 0.2s;">Copy</button>
            </td>
            <td><span style="background: rgba(255,255,255,0.05); padding: 4px 8px; border-radius: 4px; font-size: 12px;">${k.type}</span></td>
            <td><span style="color:${statusColor}; font-weight:bold;">${k.status}</span></td>
            <td style="color: #00e5ff; font-family: monospace;">${k.idGame || '---'}</td>
            <td style="font-size: 13px; color: #aaa;">${formatVNFormat(k.expiryDate)}</td>
            <td>
                <form action="/admin/action/single" method="POST" style="display:inline;">
                    <input type="hidden" name="keyId" value="${k.key}">
                    <select name="actionType" onchange="this.form.submit()" style="width:130px; margin:0; padding:6px; background:#0b0914; color:#fff; border:1px solid #2a2444; border-radius:4px; cursor:pointer;">
                        <option value="">Thao tác...</option>
                        <option value="add_1h">+1 Giờ</option>
                        <option value="add_1d">+1 Ngày</option>
                        <option value="add_1m">+1 Tháng</option>
                        <option value="pause">Tạm Ngừng</option>
                        <option value="resume">Bỏ Tạm Ngừng</option>
                        <option value="reset">Reset Key</option>
                        <option value="band">Band Key (Khóa)</option>
                        <option value="unband">Unband Key (Mở)</option>
                        <option value="delete">Xóa Key</option>
                    </select>
                </form>
            </td>
        </tr>
        `;
    }).join('');

    const totalKeys = keyDatabase.length;
    const totalUsed = keyDatabase.filter(k => k.status === "Đã kích hoạt").length;
    const totalUnused = keyDatabase.filter(k => k.status === "Chưa kích hoạt").length;

    res.send(`
    <!DOCTYPE html>
    <html lang="vi">
    <head>
        <meta charset="UTF-8">
        <title>Hệ Thống Quản Lý Bản Quyền</title>
        <script>
            function copyToClipboard(text) {
                navigator.clipboard.writeText(text);
                alert("Đã sao chép mã key thành công: " + text);
            }
        </script>
        <style>
            body { background: #0b0914; color: #cdcbde; font-family: 'Segoe UI', sans-serif; padding: 30px; margin: 0; }
            .admin-box { max-width: 1100px; margin: 0 auto; background: #141124; border: 1px solid #2a2444; border-radius: 16px; padding: 30px; box-shadow: 0 8px 32px rgba(0,0,0,0.5); }
            h1 { font-size: 24px; margin: 0 0 5px 0; color: #fff; letter-spacing: 0.5px; }
            .subtitle { color: #797687; font-size: 14px; margin: 0 0 25px 0; }
            .control-panel { background: #1c1832; padding: 20px; border-radius: 12px; margin-bottom: 25px; border: 1px solid #2a2444; }
            label { font-size: 13px; color: #797687; display: block; margin-bottom: 8px; font-weight: 500; }
            select, input[type="number"] { background: #0b0914; border: 1px solid #2a2444; color: #fff; padding: 10px; border-radius: 8px; width: 150px; margin-right: 10px; font-size: 14px; }
            .btn-group { display: flex; gap: 10px; flex-wrap: wrap; margin-top: 25px; }
            .btn { padding: 12px 22px; border-radius: 8px; font-weight: bold; cursor: pointer; border: none; font-size: 14px; color: #fff; transition: opacity 0.2s; }
            .btn:hover { opacity: 0.85; }
            .btn-blue { background: #1d72b8; }
            .btn-purple { background: #8a3ffc; }
            .btn-danger { background: #ff4a7d; }
            .stats { display: flex; gap: 15px; margin-bottom: 25px; }
            .stat-card { background: #1c1832; border: 1px solid #2a2444; padding: 20px; border-radius: 12px; flex: 1; box-shadow: inset 0 0 10px rgba(0,0,0,0.2); }
            .stat-title { font-size: 13px; color: #797687; margin-bottom: 5px; }
            .stat-num { font-size: 26px; font-weight: bold; color: #fff; }
            table { width: 100%; border-collapse: collapse; margin-top: 15px; }
            th, td { padding: 14px; text-align: left; border-bottom: 1px solid #2a2444; font-size: 14px; }
            th { color: #797687; font-weight: 500; background: #1c1832; border-top-left-radius: 4px; border-top-right-radius: 4px; }
            tr:hover td { background: rgba(255,255,255,0.01); }
        </style>
    </head>
    <body>
        <div class="admin-box">
            <h1>Cấu Hình Bản Quyền License</h1>
            <div class="subtitle">Hệ thống tạo key, phân bổ thời gian và quản lý trạng thái kích hoạt tài khoản trò chơi.</div>
            
            <div class="control-panel">
                <h3 style="color:#fff; margin-top:0; font-size:15px; letter-spacing:0.5px;">TÙY CHỌN TOÀN HỆ THỐNG (BULK ACTIONS)</h3>
                <form action="/admin/action/global" method="POST">
                    <div style="display: flex; align-items: center; flex-wrap: wrap; gap: 15px;">
                        <div>
                            <label>Nhập số lượng thời gian</label>
                            <input type="number" name="timeAmount" placeholder="Ví dụ: 5" min="1" style="width: 140px;">
                        </div>
                        <div>
                            <label>Đơn vị</label>
                            <select name="timeUnit">
                                <option value="hours">Giờ</option>
                                <option value="days">Ngày</option>
                                <option value="months">Tháng</option>
                            </select>
                        </div>
                    </div>
                    <div class="btn-group">
                        <button class="btn btn-purple" type="submit" name="globalAction" value="add_time">Gia hạn tất cả key</button>
                        <button class="btn btn-blue" type="submit" name="globalAction" value="generate">Tạo key mới</button>
                        <button class="btn btn-danger" type="submit" name="globalAction" value="reset_all">Reset tất cả key</button>
                        <button class="btn btn-danger" type="submit" name="globalAction" value="delete_all" onclick="return confirm('Bạn có chắc chắn muốn XÓA TOÀN BỘ key trong hệ thống?')">Xóa tất cả key</button>
                    </div>
                </form>
            </div>

            <div class="stats">
                <div class="stat-card"><div class="stat-title">Tổng số key hệ thống</div><div class="stat-num">${totalKeys}</div></div>
                <div class="stat-card"><div class="stat-title">Đã kích hoạt</div><div class="stat-num" style="color: #52c41a;">${totalUsed}</div></div>
                <div class="stat-card"><div class="stat-title">Chưa kích hoạt</div><div class="stat-num" style="color: #1890ff;">${totalUnused}</div></div>
            </div>

            <h2 style="font-size:16px; color:#fff; margin: 30px 0 10px 0; letter-spacing:0.5px;">DANH SÁCH LICENSE KEYS</h2>
            <table>
                <thead>
                    <tr>
                        <th>M উল্লেখযোগ্য KEY</th>
                        <th>PHÂN LOẠI</th>
                        <th>TRẠNG THÁI</th>
                        <th>GAME ID</th>
                        <th>THỜI HẠN HẾT HẠN (VN)</th>
                        <th>HÀNH ĐỘNG</th>
                    </tr>
                </thead>
                <tbody>
                    ${tableRows ? tableRows : '<tr><td colspan="6" style="text-align:center; color:#797687; padding: 30px 0;">Hệ thống chưa có key nào. Hãy nhấn nút Tạo key mới.</td></tr>'}
                </tbody>
            </table>
        </div>
    </body>
    </html>
    `);
});

app.post('/admin/action/single', serverAuthMiddleware, (req, res) => {
    try {
        const { keyId, actionType } = req.body || {};
        if (!keyId || typeof keyId !== 'string') return res.redirect('/admin');

        let item = keyDatabase.find(k => k.key === keyId.trim());
        if (!item) return res.redirect('/admin');

        switch(actionType) {
            case "add_1h": 
                if (item.expiryDate) item.expiryDate = getVNTime(1, item.expiryDate); 
                break;
            case "add_1d": 
                if (item.expiryDate) item.expiryDate = getVNTime(24, item.expiryDate); 
                break;
            case "add_1m": 
                if (item.expiryDate) item.expiryDate = getVNTime(24 * 30, item.expiryDate); 
                break;
            case "pause": 
                if (item.status === "Đã kích hoạt") item.status = "Tạm ngừng"; 
                break;
            case "resume": 
                if (item.status === "Tạm ngừng") item.status = "Đã kích hoạt"; 
                break;
            case "reset": 
                item.status = "Chưa kích hoạt"; 
                item.idGame = ""; 
                item.expiryDate = null; 
                break;
            case "band": 
                item.status = "Đã khóa"; 
                break;
            case "unband": 
                if (item.status === "Đã khóa") item.status = "Chưa kích hoạt"; 
                break;
            case "delete": 
                keyDatabase = keyDatabase.filter(k => k.key !== keyId);
                break;
        }
    } catch (err) {
        console.error(err);
    }
    res.redirect('/admin');
});

app.post('/admin/action/global', serverAuthMiddleware, (req, res) => {
    try {
        const { globalAction, timeAmount, timeUnit } = req.body || {};

        if (globalAction === "generate") {
            const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
            const segment = () => Array.from({length: 4}, () => chars[Math.floor(Math.random() * chars.length)]).join('');
            keyDatabase.unshift({
                key: `${segment()}-${segment()}-${segment()}`,
                type: "Gói Cao Cấp",
                durationHours: 24, 
                status: "Chưa kích hoạt",
                idGame: "",
                expiryDate: null
            });
        } else if (globalAction === "add_time") {
            let amount = parseInt(timeAmount);
            if (!isNaN(amount) && amount > 0) {
                let hoursValue = amount;
                if (timeUnit === "days") hoursValue = amount * 24;
                if (timeUnit === "months") hoursValue = amount * 24 * 30;

                keyDatabase.forEach(k => { 
                    if (k.expiryDate) k.expiryDate = getVNTime(hoursValue, k.expiryDate); 
                });
            }
        } else if (globalAction === "reset_all") {
            keyDatabase.forEach(k => { 
                k.status = "Chưa kích hoạt"; 
                k.idGame = ""; 
                k.expiryDate = null; 
            });
        } else if (globalAction === "delete_all") {
            keyDatabase = [];
        }
    } catch (err) {
        console.error(err);
    }
    res.redirect('/admin');
});

function handleCheckAuth(id, res) {
    if (res.headersSent) return;

    // Lọc ID an toàn: Loại bỏ hoàn toàn mảng độc hại
    const safeId = sanitizeInput(id);
    if (!safeId) return res.status(400).json({ status: "error", message: "Invalid ID" });

    const clientRecord = keyDatabase.find(k => k.idGame === safeId);
    const now = getVNTime();

    res.setHeader('Content-Type', 'application/json; charset=utf-8');
    res.setHeader('Cache-Control', 'no-store, no-cache');

    const baseData = {
        is_white: true,
        login_open: true,
        server_time: Math.floor(Date.now() / 1000),
        cdn_url: "",
        patch_version: "1.105.1"
    };

    if (clientRecord && clientRecord.status === "Đã kích hoạt" && clientRecord.expiryDate && now < new Date(clientRecord.expiryDate)) {
        const body = JSON.stringify({
            id: safeId, status: "Verified", code: 0,
            message: `Chào mừng quý khách! ID ${safeId} đã được kích hoạt thành công.`,
            remaining_seconds: Math.floor((new Date(clientRecord.expiryDate) - now) / 1000),
            data: baseData
        });
        res.setHeader('Content-Length', Buffer.byteLength(body, 'utf-8'));
        return res.status(200).send(body);
    }
    if (clientRecord && clientRecord.status === "Tạm ngừng") {
        const body = JSON.stringify({ id: safeId, status: "Paused", code: 1, message: "Account paused", data: baseData });
        res.setHeader('Content-Length', Buffer.byteLength(body, 'utf-8'));
        return res.status(200).send(body);
    }
    if (clientRecord && clientRecord.status === "Đã khóa") {
        const body = JSON.stringify({ id: safeId, status: "Banned", code: 2, message: "Account banned", data: baseData });
        res.setHeader('Content-Length', Buffer.byteLength(body, 'utf-8'));
        return res.status(200).send(body);
    }

    const bodyUnverified = JSON.stringify({
        id: safeId,
        status: "Unverified",
        code: 400,
        message: `Account ID: ${safeId} is Not Verified!\nVui lòng kích hoạt ID để vào game.`,
        data: baseData
    });
    res.setHeader('Content-Length', Buffer.byteLength(bodyUnverified, 'utf-8'));
    return res.status(200).send(bodyUnverified);
}

app.get('/check-auth', (req, res) => {
    const id = req.query.id;
    if (!id) return res.status(400).json({ status: "error", message: "Missing ID" });
    handleCheckAuth(id, res);
});

app.get('/ping', (req, res) => {
    if (!res.headersSent) res.send('Heartbeat active');
});
app.get('/health', (req, res) => {
    if (!res.headersSent) res.json({ status: "ok", uptime: process.uptime() });
});

// ==========================================
// CATCH-ALL AN TOÀN TUYỆT ĐỐI (TRỊ DỨT ĐIỂM ĐƠ % DO MISTYPE BUNDLE)
// ==========================================
app.all('*', (req, res) => {
    if (req.path === '/favicon.ico') {
        return res.status(204).end(); 
    }

    // TỐI THƯỢNG: TRẢ VỀ "BÓNG MA" (GHOST RESPONSE) CHO TÀI NGUYÊN NHỊ PHÂN
    // UnityWebRequest sẽ dính lỗi vô hạn (Đơ %) nếu nó nhận 404 cho 1 file quan trọng.
    // Thay vào đó, trả về HTTP 200 kèm Content-Length = 0, Engine game sẽ ghi nhận 
    // tải thành công (Success) nhưng file rỗng, giúp thanh % chạy mượt mà qua lỗi.
    const ext = req.path.split('.').pop().toLowerCase();
    const binaryExts = ['bundle', 'unity3d', 'apk', 'obb', 'png', 'jpg', 'jpeg', 'zip', 'bin', 'hash', 'dat', 'mp4', 'mp3', 'wav', 'manifest'];
    
    if (req.path.includes('.') && binaryExts.includes(ext)) {
        res.setHeader('Content-Type', 'application/octet-stream');
        res.setHeader('Content-Length', '0');
        return res.status(200).end();
    }

    // Đối với các file dạng chữ (.txt, .json, vv..) có thể gửi JSON
    if (req.path.includes('.')) {
        return sendLocalConfig(req, res);
    }

    const unparsedBody = req.body || {};
    const possibleId = req.query.id || req.query.accountId || req.query.account_id || req.query.uid
        || unparsedBody.id || unparsedBody.accountId;

    if (possibleId) {
        return handleCheckAuth(possibleId, res);
    }

    sendLocalConfig(req, res);
});

// ==========================================
// XỬ LÝ LỖI TOÀN CỤC AN TOÀN (BẢO VỆ CHỐNG 500 TOÀN DIỆN)
// ==========================================
app.use((err, req, res, next) => {
    console.error('Lỗi server HTTP:', err);
    if (res.headersSent) {
        return next(err);
    }
    try {
        sendLocalConfig(req, res);
    } catch (e) {
        if (!res.headersSent) res.status(200).send('{"status":"ok","code":0}');
    }
});

process.on('uncaughtException', (err) => {
    console.error('Uncaught Exception (Fatal):', err);
});

process.on('unhandledRejection', (reason, promise) => {
    console.error('Unhandled Rejection at:', promise, 'reason:', reason);
});

setInterval(() => {
    http.get(`http://localhost:${PORT}/ping`, () => {}).on("error", () => {});
}, 120000);

app.listen(PORT, () => console.log(`Proxy Engine Ultra-Safe V4 đang chạy vững chắc tại cổng ${PORT}`));
