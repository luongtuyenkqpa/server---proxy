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

// =========================================================================
// HỆ THỐNG TỐI TÂN LẤY TÊN NHÂN VẬT FREE FIRE TỪ GARENA API (ĐÃ NÂNG CẤP)
// =========================================================================
async function fetchFFNickname(idGame) {
    const uid = String(idGame).trim();
    
    // Danh sách các cổng API của Garena được cấu hình Header giả lập trình duyệt nâng cao
    const endpoints = [
        {
            url: 'https://shop.garena.sg/api/auth/player_id_login',
            origin: 'https://shop.garena.sg',
            referer: 'https://shop.garena.sg/app/100067/idlogin'
        },
        {
            url: 'https://shop.garena.my/api/auth/player_id_login',
            origin: 'https://shop.garena.my',
            referer: 'https://shop.garena.my/app/100067/idlogin'
        },
        {
            url: 'https://shop.garena.ph/api/auth/player_id_login',
            origin: 'https://shop.garena.ph',
            referer: 'https://shop.garena.ph/app/100067/idlogin'
        }
    ];

    for (const endpoint of endpoints) {
        try {
            const controller = new AbortController();
            const timeoutId = setTimeout(() => controller.abort(), 4000); // Hủy kết nối sau 4 giây nếu cổng bị treo

            const response = await fetch(endpoint.url, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Accept': 'application/json, text/plain, */*',
                    'Accept-Language': 'vi-VN,vi;q=0.9,fr-FR;q=0.8,fr;q=0.7,en-US;q=0.6,en;q=0.5',
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36',
                    'Origin': endpoint.origin,
                    'Referer': endpoint.referer,
                    'Sec-Ch-Ua': '"Chromium";v="122", "Not(A:Brand";v="24", "Google Chrome";v="122"',
                    'Sec-Ch-Ua-Mobile': '?0',
                    'Sec-Ch-Ua-Platform': '"Windows"',
                    'Sec-Fetch-Dest': 'empty',
                    'Sec-Fetch-Mode': 'cors',
                    'Sec-Fetch-Site': 'same-origin',
                    'X-Requested-With': 'XMLHttpRequest'
                },
                body: JSON.stringify({
                    app_id: 100067, // App ID mặc định của game Free Fire trên Garena
                    login_id: uid
                }),
                signal: controller.signal
            });

            clearTimeout(timeoutId);

            // Nếu phản hồi từ cổng này không thành công (ví dụ lỗi 403), chuyển sang cổng tiếp theo
            if (!response.ok) continue;

            const data = await response.json();
            
            // Trường hợp tìm thấy tên hợp lệ
            if (data && data.nickname) {
                return data.nickname;
            }
            
            // Trường hợp Garena phản hồi trực tiếp rằng UID không tồn tại
            if (data && (data.error === 'player_not_found' || data.error_code === 10013)) {
                return "ID không tồn tại";
            }
        } catch (error) {
            console.error(`Lỗi cổng kết nối ${endpoint.url}:`, error.message);
            // Tiếp tục vòng lặp thử các cổng dự phòng khác
        }
    }
    return "Không tìm thấy tên";
}

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

const renderNotificationPage = (title, message, isSuccess = false, type = "error") => {
    let color = "#ff4a7d"; let borderColor = "#ff4a7d";
    if (isSuccess) { color = "#52c41a"; borderColor = "#52c41a"; }
    else if (type === "warning") { color = "#ffaa00"; borderColor = "#ffaa00"; }
    return `<!DOCTYPE html><html lang="vi"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"><title>${title}</title><style>body { background: #0b0914; color: #fff; font-family: sans-serif; display: flex; justify-content: center; align-items: center; height: 100vh; margin: 0; } .card { background: #141124; padding: 40px 30px; border-radius: 16px; border: 1px solid ${borderColor}; width: 380px; text-align: center; box-sizing: border-box; } h2 { color: ${color}; margin-top: 0; } p { color: #cdcbde; } .btn-back { display: inline-block; width: 100%; padding: 12px; background: #2a2444; border: 1px solid #3d3566; color: #fff; border-radius: 8px; text-decoration: none; font-weight: bold; }</style></head><body><div class="card"><h2>${title}</h2><p>${message}</p><a class="btn-back" href="/">QUAY LẠI TRANG CHỦ</a></div></body></html>`;
};

// ==========================================
// CỔNG KẾT NỐI API CHO ĐIỆN THOẠI
// ==========================================
app.post('/api/activate', async (req, res) => {
    res.setHeader('Content-Type', 'application/json; charset=utf-8');
    const { idGame, licenseKey } = req.body || {};

    if (!licenseKey || !idGame) {
        return res.status(400).json({ status: "error", message: "Vui lòng nhập đầy đủ ID và Key." });
    }

    const safeKey = String(licenseKey).trim();
    const safeId = String(idGame).trim();
    const now = getVNTime();

    let targetRecord = keyDatabase.find(k => k.key === safeKey);

    if (!targetRecord) {
        return res.status(404).json({ status: "error", message: "Mã key license không tồn tại trên hệ thống." });
    }
    if (targetRecord.status === "Đã khóa") {
        return res.status(403).json({ status: "error", message: "Mã key này đã bị khóa vĩnh viễn." });
    }
    if (targetRecord.status === "Tạm ngừng") {
        return res.status(403).json({ status: "error", message: "Key đang bảo trì bởi quản trị viên." });
    }
    if (targetRecord.expiryDate && now >= new Date(targetRecord.expiryDate)) {
        return res.status(403).json({ status: "error", message: "Mã bản quyền này đã hết hạn sử dụng." });
    }
    if (targetRecord.status === "Đã kích hoạt" && targetRecord.idGame !== safeId) {
        return res.status(403).json({ status: "error", message: "Key đã được liên kết với một ID Game khác." });
    }

    // Tự động tìm tên Free Fire từ API
    const playerName = await fetchFFNickname(safeId);

    let expiryVN = targetRecord.expiryDate ? new Date(targetRecord.expiryDate) : getVNTime(targetRecord.durationHours);
    targetRecord.expiryDate = expiryVN;
    targetRecord.status = "Đã kích hoạt";
    targetRecord.idGame = safeId;
    targetRecord.playerName = playerName; // Lưu vào database tạm thời

    return res.status(200).json({
        status: "success",
        message: "Xác thực bản quyền thành công!",
        idGame: safeId,
        playerName: playerName,
        expiry: formatVNFormat(expiryVN)
    });
});

// Giao diện Web kích hoạt thủ công
app.get('/', (req, res) => {
    res.send(`<!DOCTYPE html><html lang="vi"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"><title>Hệ Thống Xác Thực Bản Quyền</title><style>body { background: #0b0914; color: #fff; font-family: sans-serif; display: flex; justify-content: center; align-items: center; height: 100vh; margin: 0; position: relative; } .menu-trigger { position: absolute; top: 20px; left: 20px; cursor: pointer; } .side-menu { position: absolute; top: 0; left: -250px; width: 250px; height: 100%; background: #141124; border-right: 1px solid #2a2444; transition: 0.3s; padding: 60px 20px; box-sizing: border-box; } .side-menu.active { left: 0; } .side-menu a { display: block; color: #cdcbde; text-decoration: none; padding: 12px; background: #1c1832; border-radius: 6px; text-align: center; } .activation-box { background: #141124; padding: 35px; border-radius: 16px; border: 1px solid #2a2444; width: 380px; box-shadow: 0 8px 32px rgba(0,0,0,0.5); } .notice { background: rgba(138, 63, 252, 0.1); border: 1px solid #8a3ffc; padding: 12px; border-radius: 8px; font-size: 13px; color: #cdcbde; margin-bottom: 20px; text-align: center; } input { width: 100%; padding: 12px; margin-bottom: 15px; border-radius: 8px; border: 1px solid #2a2444; background: #0b0914; color: #fff; box-sizing: border-box; } .btn-submit { width: 100%; padding: 14px; background: #8a3ffc; border: none; color: #fff; font-weight: bold; border-radius: 8px; cursor: pointer; }</style></head><body><div class="menu-trigger" onclick="toggleMenu()">☰</div><div class="side-menu" id="sideMenu"><a href="/admin">Đăng Nhập Quản Trị</a></div><div class="activation-box"><h2>Kích Hoạt Bản Quyền</h2><div class="notice">Vui lòng kích hoạt key và nhập ID Game để xác thực trạng thái tài khoản trên hệ thống máy chủ.</div><form action="/activate" method="POST"><label>ID GAME</label><input type="text" name="idGame" placeholder="Nhập ID Game của bạn" required><label>MÃ KEY LICENSE</label><input type="text" name="licenseKey" placeholder="64KA-XXXX-XXXX-XXXX" required><button class="btn-submit" type="submit">KÍCH HOẠT NGAY</button></form></div><script>function toggleMenu() { document.getElementById('sideMenu').classList.toggle('active'); }</script></body></html>`);
});

app.post('/activate', async (req, res) => {
    try {
        const { idGame, licenseKey } = req.body || {};
        if (!licenseKey || !idGame) return res.send(renderNotificationPage("DỮ LIỆU KHÔNG HỢP LỆ", "Vui lòng điền đầy đủ thông tin.", false, "error"));

        const safeKey = licenseKey.trim();
        const safeId = idGame.trim();
        let targetRecord = keyDatabase.find(k => k.key === safeKey);
        const now = getVNTime();

        if (!targetRecord) return res.send(renderNotificationPage("LỖI XÁC THỰC", "Mã key license không tồn tại.", false, "error"));
        if (targetRecord.status === "Đã khóa") return res.send(renderNotificationPage("KEY BỊ KHÓA", "Mã key này đã bị vô hiệu hóa.", false, "error"));
        if (targetRecord.status === "Tạm ngừng") return res.send(renderNotificationPage("TẠM NGỪNG", "Mã key đang bảo trì.", false, "warning"));
        if (targetRecord.expiryDate && now >= new Date(targetRecord.expiryDate)) return res.send(renderNotificationPage("KEY HẾT HẠN", "Mã bản quyền này đã hết hạn.", false, "error"));
        if (targetRecord.status === "Đã kích hoạt" && targetRecord.idGame !== safeId) return res.send(renderNotificationPage("SAI ID", "Key đã được liên kết với ID khác.", false, "error"));

        // Lấy tên nhân vật từ API
        const playerName = await fetchFFNickname(safeId);

        const startVN = getVNTime();
        let expiryVN = targetRecord.expiryDate ? new Date(targetRecord.expiryDate) : getVNTime(targetRecord.durationHours);
        targetRecord.expiryDate = expiryVN;
        targetRecord.status = "Đã kích hoạt";
        targetRecord.idGame = safeId;
        targetRecord.playerName = playerName;

        res.send(`<!DOCTYPE html><html lang="vi"><head><meta charset="UTF-8"><title>Thành Công</title><style>body { background: #0b0914; color: #fff; font-family: sans-serif; display: flex; justify-content: center; align-items: center; height: 100vh; } .card { background: #141124; padding: 30px; border-radius: 16px; border: 1px solid #52c41a; width: 400px; } .row { background: #0b0914; padding: 14px; margin: 12px 0; border-radius: 8px; border-left: 4px solid #8a3ffc; display: flex; justify-content: space-between; align-items: center; }</style></head><body><div class="card"><h2>KÍCH HOẠT THÀNH CÔNG</h2><div class="row"><span>ID Game:</span><strong>${safeId}</strong></div><div class="row"><span>Tên nhân vật:</span><strong style="color: #00e5ff;">${playerName}</strong></div><div class="row"><span>Hết hạn:</span><strong>${formatVNFormat(expiryVN)}</strong></div><a href="/" style="color:#8a3ffc; display:block; text-align:center; margin-top:20px;">Quay lại</a></div></body></html>`);
    } catch (err) {
        sendLocalConfig(req, res);
    }
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
            <td style="color: #00e5ff;">
                <div>${k.idGame || '---'}</div>
                ${k.playerName ? `<small style="color: #cdcbde; display: block; margin-top: 4px; font-style: italic;">(${k.playerName})</small>` : ''}
            </td>
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

    res.send(`<!DOCTYPE html><html><head><meta charset="UTF-8"><title>Hệ Thống Quản Lý Bản Quyền</title><style>body { background: #0b0914; color: #cdcbde; font-family: sans-serif; padding: 30px; } .admin-box { max-width: 1100px; margin: 0 auto; background: #141124; border: 1px solid #2a2444; border-radius: 16px; padding: 30px; } .control-panel { background: #1c1832; padding: 20px; border-radius: 12px; margin-bottom: 25px; border: 1px solid #2a2444; } select, input[type="number"] { background: #0b0914; border: 1px solid #2a2444; color: #fff; padding: 10px; border-radius: 8px; } .btn { padding: 12px 22px; border-radius: 8px; font-weight: bold; cursor: pointer; border: none; color: #fff; margin-right: 10px; } .btn-purple { background: #8a3ffc; } .btn-blue { background: #1d72b8; } .btn-danger { background: #ff4a7d; } table { width: 100%; border-collapse: collapse; } th, td { padding: 14px; text-align: left; border-bottom: 1px solid #2a2444; } th { background: #1c1832; color: #797687; }</style></head><body><div class="admin-box"><h1>Cấu Hình Bản Quyền License</h1><div class="control-panel"><h3>TÙY CHỌN TOÀN HỆ THỐNG</h3><form action="/admin/action/global" method="POST"><input type="number" name="timeAmount" placeholder="Số lượng" min="1"> <select name="timeUnit"><option value="hours">Giờ</option><option value="days">Ngày</option><option value="months">Tháng</option></select><br><br><button class="btn btn-purple" type="submit" name="globalAction" value="add_time">Gia hạn tất cả</button><button class="btn btn-blue" type="submit" name="globalAction" value="generate">Tạo key mới</button><button class="btn btn-danger" type="submit" name="globalAction" value="reset_all">Reset tất cả</button></form></div><table><thead><tr><th>MÃ KEY</th><th>PHÂN LOẠI</th><th>TRẠNG THÁI</th><th>GAME ID (TÊN)</th><th>HẠN DÙNG (VN)</th><th>HÀNH ĐỘNG</th></tr></thead><tbody>${tableRows || '<tr><td colspan="6" style="text-align:center;">Chưa có key nào.</td></tr>'}</tbody></table></div></body></html>`);
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
            case "reset": item.status = "Chưa kích hoạt"; item.idGame = ""; item.playerName = ""; item.expiryDate = null; break;
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
            keyDatabase.unshift({ key: `${segment()}-${segment()}-${segment()}`, type: "Gói Cao Cấp", durationHours: 24, status: "Chưa kích hoạt", idGame: "", playerName: "", expiryDate: null });
        } else if (globalAction === "add_time") {
            let amount = parseInt(timeAmount);
            if (!isNaN(amount) && amount > 0) {
                let hoursValue = timeUnit === "days" ? amount * 24 : timeUnit === "months" ? amount * 24 * 30 : amount;
                keyDatabase.forEach(k => { if (k.expiryDate) k.expiryDate = getVNTime(hoursValue, k.expiryDate); });
            }
        } else if (globalAction === "reset_all") {
            keyDatabase.forEach(k => { k.status = "Chưa kích hoạt"; k.idGame = ""; k.playerName = ""; k.expiryDate = null; });
        }
    } catch (err) { console.error(err); }
    res.redirect('/admin');
});

function handleCheckAuth(id, res) {
    const safeId = sanitizeInput(id);
    if (!safeId) return res.status(400).json({ status: "error", message: "Invalid ID" });
    const clientRecord = keyDatabase.find(k => k.idGame === safeId);
    const now = getVNTime();
    const baseData = { is_white: true, login_open: true, server_time: Math.floor(Date.now() / 1000), cdn_url: "", patch_version: "1.105.1" };

    if (clientRecord && clientRecord.status === "Đã kích hoạt" && clientRecord.expiryDate && now < new Date(clientRecord.expiryDate)) {
        return res.status(200).send(JSON.stringify({ 
            id: safeId, 
            playerName: clientRecord.playerName || "", 
            status: "Verified", 
            code: 0, 
            message: "Kích hoạt thành công.", 
            remaining_seconds: Math.floor((new Date(clientRecord.expiryDate) - now) / 1000), 
            data: baseData 
        }));
    }
    return res.status(200).send(JSON.stringify({ id: safeId, status: "Unverified", code: 400, message: "ID Chưa Kích Hoạt!", data: baseData }));
}

app.get('/check-auth', (req, res) => { handleCheckAuth(req.query.id, res); });
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
    const possibleId = req.query.id || req.query.accountId || unparsedBody.id;
    if (possibleId) return handleCheckAuth(possibleId, res);
    sendLocalConfig(req, res);
});

app.use((err, req, res, next) => {
    try { sendLocalConfig(req, res); } catch (e) { res.status(200).send('{"status":"ok","code":0}'); }
});

app.listen(PORT, () => console.log(`Server Online tại cổng ${PORT}`));
