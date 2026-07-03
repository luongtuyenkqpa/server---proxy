const express = require('express');
const app = express(); 
const http = require('http');
const fs = require('fs');
const TelegramBot = require('node-telegram-bot-api');

const PORT = process.env.PORT || 3000;
const DB_FILE = './keys.json';
const STORE_FILE = './products.json';

// CẤU HÌNH TELEGRAM BOT
const TELEGRAM_TOKEN = '8714375866:AAG9r0aCCFOKtgR6B-LcFYBAnJ7x9yMs-8o';
const bot = new TelegramBot(TELEGRAM_TOKEN, { polling: true });

// ==========================================
// HỆ THỐNG CƠ SỞ DỮ LIỆU TỆP TIN (CHỐNG MẤT DỮ LIỆU KHI RENDER NGỦ)
// ==========================================
let keyDatabase = [];
let storeProducts = [];

try {
    if (fs.existsSync(DB_FILE)) keyDatabase = JSON.parse(fs.readFileSync(DB_FILE, 'utf8'));
    if (fs.existsSync(STORE_FILE)) storeProducts = JSON.parse(fs.readFileSync(STORE_FILE, 'utf8'));
} catch (e) { console.error("Lỗi nạp DB:", e); }

function saveKeys() { fs.writeFileSync(DB_FILE, JSON.stringify(keyDatabase, null, 2)); }
function saveProducts() { fs.writeFileSync(STORE_FILE, JSON.stringify(storeProducts, null, 2)); }

// ==========================================
// THIẾT LẬP MÔI TRƯỜNG CHUYÊN NGHIỆP & BẢO MẬT
// ==========================================
app.disable('x-powered-by'); 
app.set('trust proxy', 1);   

app.use((req, res, next) => {
    res.header("Access-Control-Allow-Origin", "*");
    res.header("Access-Control-Allow-Methods", "GET, POST, OPTIONS, PUT, PATCH, DELETE");
    res.header("Access-Control-Allow-Headers", "Origin, X-Requested-With, Content-Type, Accept, Authorization, X-Unity-Version, User-Agent");
    res.header("Cache-Control", "no-store, no-cache, must-revalidate, proxy-revalidate");
    if (req.method === 'OPTIONS') return res.sendStatus(200);
    next();
});

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

const ipBruteForceLog = new Map(); 
const ipBlacklist = new Set();     

const militaryFirewall = (req, res, next) => {
    const ip = req.headers['x-forwarded-for'] || req.ip || req.socket.remoteAddress;
    if (ipBlacklist.has(ip)) return res.status(403).json({ status: "cyber_defense", message: "Access denied." });
    const maliciousPattern = /(\.\.\/|select\s+.*\s+from|union\s+select|<script>|'|--|sqlmap|dirbuster|nikto)/i;
    if (maliciousPattern.test(req.url) || maliciousPattern.test(JSON.stringify(req.body))) {
        ipBlacklist.add(ip);
        return res.status(400).json({ error: "Malicious payload detected." });
    }
    next();
};
app.use(militaryFirewall);

function getVNTime(offsetHours = 0, baseDate = null) {
    const current = baseDate ? new Date(baseDate) : new Date();
    if (offsetHours !== 0) current.setTime(current.getTime() + (offsetHours * 60000 * 60));
    return current;
}

function formatVNFormat(dateObj) {
    if (!dateObj) return "Chưa kích hoạt";
    const pad = (n) => n.toString().padStart(2, '0');
    const d = new Date(dateObj);
    return `${pad(d.getDate())}/${pad(d.getMonth() + 1)}/${d.getFullYear()} ${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`;
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
    const optimizedResponse = {
        "status": "ok", "code": 0, "message": "success", "server_status": "online", "region": "VN",
        "data": { "is_white": true, "login_open": true, "server_time": Math.floor(Date.now() / 1000) }
    };
    res.status(200).send(JSON.stringify(optimizedResponse));
};

// =========================================================================
// API ĐIỆN THOẠI (FIX CHỮ O THÀNH SỐ 0 TRIỆT ĐỂ)
// =========================================================================
const handleActivationLogic = async (req, res) => {
    res.setHeader('Content-Type', 'application/json; charset=utf-8');
    const { licenseKey } = req.body || {};
    const ip = req.headers['x-forwarded-for'] || req.ip;

    const attempts = ipBruteForceLog.get(ip) || 0;
    if (attempts > 5) return res.status(429).json({ status: "error", message: "Quá nhiều yêu cầu. Vui lòng thử lại sau." });
    if (!licenseKey) return res.status(400).json({ status: "error", message: "Vui lòng nhập Key." });

    const safeKey = String(licenseKey).trim().toUpperCase().replace(/O/g, '0');
    const now = getVNTime();

    let targetRecord = keyDatabase.find(k => k.key.trim().toUpperCase().replace(/O/g, '0') === safeKey);

    if (!targetRecord) {
        ipBruteForceLog.set(ip, attempts + 1);
        await new Promise(resolve => setTimeout(resolve, 300 + Math.random() * 200));
        return res.status(404).json({ status: "error", message: "Mã key không tồn tại trên hệ thống." });
    }

    ipBruteForceLog.delete(ip);
    if (targetRecord.status === "Đã khóa") return res.status(403).json({ status: "error", message: "Key đã bị khóa." });
    if (targetRecord.status === "Tạm ngừng") return res.status(403).json({ status: "error", message: "Key đang bảo trì." });
    if (targetRecord.expiryDate && now >= new Date(targetRecord.expiryDate)) return res.status(403).json({ status: "error", message: "Key hết hạn." });

    let expiryVN = targetRecord.expiryDate ? new Date(targetRecord.expiryDate) : getVNTime(targetRecord.durationHours);
    targetRecord.expiryDate = expiryVN;
    targetRecord.status = "Đã kích hoạt";
    
    saveKeys(); 

    return res.status(200).json({ status: "success", message: "Xác thực thành công!", expiry: formatVNFormat(expiryVN) });
};

app.post('/api/activate', handleActivationLogic);
app.post('/api/aptive', handleActivationLogic);
app.post('/api/aptivate', handleActivationLogic);

// =========================================================================
// HỆ THỐNG TELEGRAM BOT & MINI APP E-COMMERCE
// =========================================================================
const getSiteUrl = () => process.env.RENDER_EXTERNAL_URL || `https://server-proxy-2c0.onrender.com`; // Thay bằng URL thật của bạn

bot.onText(/\/start/, (msg) => {
    const chatId = msg.chat.id;
    const opts = {
        reply_markup: {
            inline_keyboard: [[{ text: "🛒 MỞ CỬA HÀNG CAPCUT PRO", web_app: { url: `${getSiteUrl()}/miniapp` } }]]
        }
    };
    bot.sendMessage(chatId, "👋 Chào mừng bạn đến với Hệ Thống Bán Key Tự Động!\n\nNhấn nút bên dưới để mở cửa hàng và mua Key bản quyền.", opts);
});

// Giao diện Mini App thương mại
app.get('/miniapp', (req, res) => {
    res.send(`
    <!DOCTYPE html>
    <html lang="vi">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no">
        <title>Store Mini App</title>
        <script src="https://telegram.org/js/telegram-web-app.js"></script>
        <style>
            :root { --bg: #0b0914; --card: #141124; --primary: #8a3ffc; --text: #fff; --subtext: #797687; }
            body { background: var(--bg); color: var(--text); font-family: sans-serif; margin: 0; padding: 0; overflow-x: hidden; }
            /* Loading Screen */
            #loader { position: fixed; top:0; left:0; width: 100vw; height: 100vh; background: var(--bg); display: flex; flex-direction: column; justify-content: center; align-items: center; z-index: 9999; transition: opacity 0.5s; }
            .spinner { width: 50px; height: 50px; border: 4px solid var(--subtext); border-top-color: var(--primary); border-radius: 50%; animation: spin 1s linear infinite; }
            @keyframes spin { to { transform: rotate(360deg); } }
            
            /* Main Content */
            .header { padding: 25px 20px; text-align: center; background: linear-gradient(180deg, #1c1832 0%, var(--bg) 100%); border-bottom: 1px solid #2a2444; }
            .header h1 { margin: 0; font-size: 22px; color: var(--text); }
            .header p { margin: 5px 0 0; font-size: 13px; color: var(--subtext); }
            
            .store-container { padding: 20px; }
            .product-card { background: var(--card); border: 1px solid #2a2444; border-radius: 16px; padding: 15px; margin-bottom: 15px; position: relative; overflow: hidden; }
            .discount-badge { position: absolute; top: 10px; right: 10px; background: #ff4a7d; color: #fff; font-size: 11px; font-weight: bold; padding: 4px 8px; border-radius: 8px; }
            .prod-title { font-size: 16px; font-weight: bold; margin: 0 0 5px; }
            .prod-desc { font-size: 12px; color: var(--subtext); margin: 0 0 15px; }
            .price-row { display: flex; align-items: baseline; gap: 10px; margin-bottom: 15px; }
            .price-final { font-size: 20px; font-weight: bold; color: var(--primary); }
            .price-old { font-size: 14px; text-decoration: line-through; color: var(--subtext); }
            
            .btn-buy { width: 100%; background: var(--primary); color: #fff; border: none; padding: 12px; border-radius: 10px; font-weight: bold; font-size: 14px; cursor: pointer; }
            
            #result-screen { display: none; padding: 30px; text-align: center; }
            .key-box { background: #1c1832; border: 1px dashed var(--primary); padding: 15px; border-radius: 8px; margin: 20px 0; font-family: monospace; font-size: 18px; letter-spacing: 2px; }
        </style>
    </head>
    <body>
        <div id="loader">
            <div class="spinner"></div>
            <h3 style="margin-top: 20px; color: #8a3ffc;">Đang tải cửa hàng...</h3>
        </div>

        <div id="store-ui">
            <div class="header">
                <h1>⚡ CỬA HÀNG BẢN QUYỀN</h1>
                <p>Hệ thống cung cấp License tự động 24/7</p>
            </div>
            <div class="store-container" id="product-list">
                <!-- Data loaded via JS -->
            </div>
        </div>

        <div id="result-screen">
            <h2 style="color: #52c41a;">✅ THÀNH CÔNG!</h2>
            <p>Mã Key của bạn đã được tạo. Hãy sao chép và dán vào ứng dụng:</p>
            <div class="key-box" id="generated-key">XXXX-XXXX-XXXX</div>
            <button class="btn-buy" onclick="Telegram.WebApp.close()">ĐÓNG ỨNG DỤNG</button>
        </div>

        <script>
            const tg = window.Telegram.WebApp;
            tg.expand();
            
            // Xóa Loading Screen sau 1.5s để tạo cảm giác load data
            setTimeout(() => {
                document.getElementById('loader').style.opacity = '0';
                setTimeout(() => document.getElementById('loader').style.display = 'none', 500);
            }, 1200);

            // Fetch Data
            fetch('/api/products')
                .then(res => res.json())
                .then(products => {
                    const list = document.getElementById('product-list');
                    if(products.length === 0) {
                        list.innerHTML = "<p style='text-align:center; color:#797687'>Cửa hàng hiện đang trống.</p>";
                        return;
                    }
                    
                    products.forEach(p => {
                        if(!p.isActive) return;
                        const oldPriceStr = p.discountPercent > 0 ? \`<span class="price-old">\${p.price.toLocaleString()}đ</span>\` : '';
                        const finalPrice = p.price - (p.price * (p.discountPercent / 100));
                        const discountBadge = p.discountPercent > 0 ? \`<div class="discount-badge">-\${p.discountPercent}%</div>\` : '';
                        
                        list.innerHTML += \`
                            <div class="product-card">
                                \${discountBadge}
                                <h3 class="prod-title">\${p.name}</h3>
                                <p class="prod-desc">⏱ Thời lượng: \${p.durationHours} giờ</p>
                                <div class="price-row">
                                    <span class="price-final">\${finalPrice.toLocaleString()}đ</span>
                                    \${oldPriceStr}
                                </div>
                                <button class="btn-buy" onclick="buyProduct('\${p.id}')">MUA NGAY</button>
                            </div>
                        \`;
                    });
                });

            function buyProduct(prodId) {
                tg.showConfirm("Xác nhận tạo mã kích hoạt cho gói này?", (agreed) => {
                    if(agreed) {
                        fetch('/api/buy', {
                            method: 'POST', headers: { 'Content-Type': 'application/json' },
                            body: JSON.stringify({ productId: prodId, user: tg.initDataUnsafe?.user?.id })
                        })
                        .then(res => res.json())
                        .then(data => {
                            if(data.status === 'success') {
                                document.getElementById('store-ui').style.display = 'none';
                                document.getElementById('result-screen').style.display = 'block';
                                document.getElementById('generated-key').innerText = data.key;
                            } else {
                                tg.showAlert("Lỗi: " + data.message);
                            }
                        });
                    }
                });
            }
        </script>
    </body>
    </html>
    `);
});

// Lấy danh sách sản phẩm
app.get('/api/products', (req, res) => res.json(storeProducts));

// Xử lý logic mua hàng trên Mini App
app.post('/api/buy', (req, res) => {
    const { productId } = req.body;
    const prod = storeProducts.find(p => p.id === productId);
    if (!prod || !prod.isActive) return res.status(400).json({ status: 'error', message: 'Sản phẩm không hợp lệ' });

    // Sinh mã Key tự động sau khi bấm Mua
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
    const segment = () => Array.from({length: 4}, () => chars[Math.floor(Math.random() * chars.length)]).join('');
    const newKey = `${segment()}-${segment()}-${segment()}`;

    keyDatabase.unshift({
        key: newKey, type: prod.name, durationHours: prod.durationHours,
        status: "Chưa kích hoạt", expiryDate: null
    });
    saveKeys();

    res.json({ status: 'success', key: newKey });
});


// =========================================================================
// QUẢN TRỊ ADMIN (TÍCH HỢP 2 TAB: QUẢN LÝ KEY & QUẢN LÝ STORE)
// =========================================================================
app.get('/', (req, res) => { res.redirect('/login'); });

app.get('/login', (req, res) => {
    res.send(`<!DOCTYPE html><html><head><meta charset="UTF-8"><title>Admin Login</title><style>body { background: #0b0914; color: #fff; font-family: sans-serif; display: flex; justify-content: center; align-items: center; height: 100vh; } .login-box { background: #141124; padding: 30px; border-radius: 12px; border: 1px solid #2a2444; width: 320px; } input { width: 100%; padding: 12px; margin: 10px 0; background: #0b0914; color: #fff; border: 1px solid #2a2444; border-radius: 6px; box-sizing: border-box; } button { width: 100%; padding: 12px; background: #8a3ffc; color: #fff; border: none; border-radius: 6px; font-weight: bold; cursor: pointer; }</style></head><body><div class="login-box"><h3 style="text-align:center;">ADMIN LOGIN</h3><form action="/login" method="POST"><input type="text" name="username" placeholder="Tài khoản" required><input type="password" name="password" placeholder="Mật khẩu" required><button type="submit">Đăng Nhập</button></form></div></body></html>`);
});

app.post('/login', (req, res) => {
    const { username, password } = req.body || {};
    if (username === 'admin' && password === '120510@') {
        res.send(`<script>document.cookie = "admin_token=session_verified_120510; path=/; max-age=86400; SameSite=Strict"; window.location.href = '/admin';</script>`);
    } else {
        res.send(`<h3 style="color:#ff4a7d; text-align:center;">Sai thông tin!</h3><p style="text-align:center;"><a href="/login" style="color:#8a3ffc;">Thử lại</a></p>`);
    }
});

const serverAuthMiddleware = (req, res, next) => {
    const token = getCookieByName(req.headers.cookie, 'admin_token');
    if (token === 'session_verified_120510') next(); else res.redirect('/login');
};

app.get('/admin', serverAuthMiddleware, (req, res) => {
    // 1. Render Table Keys
    let tableRows = keyDatabase.map(k => {
        let statusColor = k.status === "Đã kích hoạt" ? "#52c41a" : (k.status === "Đã khóa" ? "#ff4a7d" : "#797687");
        return `<tr>
            <td style="color: #fff; font-family: monospace;">${k.key}</td>
            <td>${k.type}</td>
            <td><span style="color:${statusColor}; font-weight:bold;">${k.status}</span></td>
            <td>${formatVNFormat(k.expiryDate)}</td>
            <td>
                <form action="/admin/action/single" method="POST" style="display:inline;">
                    <input type="hidden" name="keyId" value="${k.key}">
                    <select name="actionType" onchange="this.form.submit()" style="padding:6px; background:#0b0914; color:#fff; border:1px solid #2a2444; border-radius:4px;">
                        <option value="">Thao tác...</option>
                        <option value="add_1d">+1 Ngày</option>
                        <option value="reset">Reset Key</option>
                        <option value="delete">Xóa Key</option>
                    </select>
                </form>
            </td>
        </tr>`;
    }).join('');

    // 2. Render Table Products
    let prodRows = storeProducts.map(p => {
        return `<tr>
            <td>${p.name}</td>
            <td>${p.durationHours} giờ</td>
            <td>${p.price.toLocaleString()}đ</td>
            <td><span style="color:#ff4a7d">-${p.discountPercent}%</span></td>
            <td>${p.isActive ? '<span style="color:#52c41a">Đang bán</span>' : '<span style="color:#797687">Ẩn</span>'}</td>
            <td>
                <form action="/admin/action/product" method="POST" style="display:inline;">
                    <input type="hidden" name="prodId" value="${p.id}">
                    <button name="action" value="toggle" style="background:#1d72b8; color:#fff; border:none; padding:5px; border-radius:4px; cursor:pointer;">Bật/Tắt</button>
                    <button name="action" value="delete" style="background:#ff4a7d; color:#fff; border:none; padding:5px; border-radius:4px; cursor:pointer;">Xóa</button>
                </form>
            </td>
        </tr>`;
    }).join('');

    res.send(`
    <!DOCTYPE html><html><head><meta charset="UTF-8"><title>Admin Panel</title>
    <style>
        body { background: #0b0914; color: #cdcbde; font-family: sans-serif; padding: 30px; margin: 0; }
        .admin-box { max-width: 1000px; margin: 0 auto; background: #141124; border: 1px solid #2a2444; border-radius: 16px; padding: 30px; }
        .tabs { display: flex; gap: 10px; margin-bottom: 20px; }
        .tab-btn { flex: 1; padding: 15px; background: #1c1832; border: 1px solid #2a2444; color: #fff; cursor: pointer; border-radius: 8px; font-weight: bold; font-size:16px;}
        .tab-btn.active { background: #8a3ffc; border-color: #8a3ffc; }
        .tab-content { display: none; }
        .tab-content.active { display: block; }
        .control-panel { background: #1c1832; padding: 20px; border-radius: 12px; margin-bottom: 25px; border: 1px solid #2a2444; }
        select, input[type="number"], input[type="text"] { background: #0b0914; border: 1px solid #2a2444; color: #fff; padding: 10px; border-radius: 8px; margin-right:5px; margin-bottom:10px; }
        .btn { padding: 12px 22px; border-radius: 8px; font-weight: bold; cursor: pointer; border: none; color: #fff; margin-right: 10px; }
        .btn-purple { background: #8a3ffc; } .btn-blue { background: #1d72b8; } .btn-green { background: #52c41a; }
        table { width: 100%; border-collapse: collapse; margin-top:20px; }
        th, td { padding: 14px; text-align: left; border-bottom: 1px solid #2a2444; } th { background: #1c1832; color: #797687; }
    </style></head><body>
    <div class="admin-box">
        <div class="tabs">
            <button class="tab-btn active" onclick="switchTab('keys')">🔑 QUẢN LÝ KEY</button>
            <button class="tab-btn" onclick="switchTab('store')">🛒 QUẢN LÝ MINI APP STORE</button>
        </div>

        <!-- TAB KEY -->
        <div id="keys" class="tab-content active">
            <div class="control-panel">
                <h3>TẠO & GIA HẠN KEY</h3>
                <form action="/admin/action/global" method="POST">
                    <input type="number" name="timeAmount" placeholder="Số lượng" min="1"> 
                    <select name="timeUnit"><option value="hours">Giờ</option><option value="days">Ngày</option></select><br>
                    <button class="btn btn-purple" type="submit" name="globalAction" value="add_time">Gia hạn tất cả</button>
                    <button class="btn btn-blue" type="submit" name="globalAction" value="generate">Tạo 1 Key ngẫu nhiên</button>
                </form>
            </div>
            <table><thead><tr><th>MÃ KEY</th><th>PHÂN LOẠI</th><th>TRẠNG THÁI</th><th>HẠN DÙNG</th><th>HÀNH ĐỘNG</th></tr></thead><tbody>${tableRows || '<tr><td colspan="5">Trống</td></tr>'}</tbody></table>
        </div>

        <!-- TAB STORE -->
        <div id="store" class="tab-content">
            <div class="control-panel">
                <h3>THÊM GÓI SẢN PHẨM MỚI (BÁN TRÊN TELEGRAM)</h3>
                <form action="/admin/action/product" method="POST">
                    <input type="text" name="name" placeholder="Tên gói (VD: Gói VIP 1 Ngày)" required>
                    <input type="number" name="durationHours" placeholder="Thời gian (Giờ)" required>
                    <input type="number" name="price" placeholder="Giá tiền (VNĐ)" required>
                    <input type="number" name="discount" placeholder="% Giảm giá (0-100)" value="0"><br>
                    <button class="btn btn-green" type="submit" name="action" value="create">Lưu Sản Phẩm</button>
                </form>
            </div>
            <table><thead><tr><th>TÊN SẢN PHẨM</th><th>THỜI LƯỢNG</th><th>GIÁ GỐC</th><th>GIẢM GIÁ</th><th>HIỂN THỊ</th><th>HÀNH ĐỘNG</th></tr></thead><tbody>${prodRows || '<tr><td colspan="6">Chưa có sản phẩm nào.</td></tr>'}</tbody></table>
        </div>
    </div>
    <script>
        function switchTab(tabId) {
            document.querySelectorAll('.tab-content').forEach(el => el.classList.remove('active'));
            document.querySelectorAll('.tab-btn').forEach(el => el.classList.remove('active'));
            document.getElementById(tabId).classList.add('active');
            event.target.classList.add('active');
        }
    </script>
    </body></html>
    `);
});

app.post('/admin/action/single', serverAuthMiddleware, (req, res) => {
    const { keyId, actionType } = req.body || {};
    let item = keyDatabase.find(k => k.key === keyId.trim());
    if (item) {
        switch(actionType) {
            case "add_1d": if (item.expiryDate) item.expiryDate = getVNTime(24, item.expiryDate); break;
            case "reset": item.status = "Chưa kích hoạt"; item.expiryDate = null; break; 
            case "delete": keyDatabase = keyDatabase.filter(k => k.key !== keyId.trim()); break;
        }
        saveKeys(); // Cập nhật DB
    }
    res.redirect('/admin');
});

app.post('/admin/action/global', serverAuthMiddleware, (req, res) => {
    const { globalAction, timeAmount, timeUnit } = req.body || {};
    if (globalAction === "generate") {
        const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
        const segment = () => Array.from({length: 4}, () => chars[Math.floor(Math.random() * chars.length)]).join('');
        keyDatabase.unshift({ key: `${segment()}-${segment()}-${segment()}`, type: "Key Tự Do", durationHours: 24, status: "Chưa kích hoạt", expiryDate: null }); 
    } else if (globalAction === "add_time") {
        let amount = parseInt(timeAmount);
        if (!isNaN(amount) && amount > 0) {
            let hoursValue = timeUnit === "days" ? amount * 24 : amount;
            keyDatabase.forEach(k => { if (k.expiryDate) k.expiryDate = getVNTime(hoursValue, k.expiryDate); });
        }
    }
    saveKeys(); // Cập nhật DB
    res.redirect('/admin');
});

// Xử lý Thêm/Sửa/Xóa cấu hình cửa hàng
app.post('/admin/action/product', serverAuthMiddleware, (req, res) => {
    const { action, prodId, name, durationHours, price, discount } = req.body || {};
    
    if (action === "create") {
        storeProducts.push({
            id: 'PROD_' + Date.now(),
            name: name,
            durationHours: parseInt(durationHours) || 24,
            price: parseInt(price) || 0,
            discountPercent: parseInt(discount) || 0,
            isActive: true
        });
    } else if (action === "toggle") {
        let p = storeProducts.find(p => p.id === prodId);
        if (p) p.isActive = !p.isActive;
    } else if (action === "delete") {
        storeProducts = storeProducts.filter(p => p.id !== prodId);
    }
    
    saveProducts(); // Lưu File Cửa hàng
    res.redirect('/admin');
});

// =========================================================================
// KIỂM TRA XÁC THỰC CỔNG PHỤ CHO CÁC LUỒNG WILDCARD
// =========================================================================
function handleCheckAuth(licenseId, res) {
    const safeKey = sanitizeInput(licenseId);
    if (!safeKey) return res.status(400).json({ status: "error", message: "Invalid Key" });
    
    const normalizedClientKey = safeKey.toUpperCase().replace(/O/g, '0');
    const clientRecord = keyDatabase.find(k => k.key.trim().toUpperCase().replace(/O/g, '0') === normalizedClientKey);
    const now = getVNTime();
    const baseData = { is_white: true, login_open: true, server_time: Math.floor(Date.now() / 1000), cdn_url: "", patch_version: "1.105.1" };

    if (clientRecord && clientRecord.status === "Đã kích hoạt" && clientRecord.expiryDate && now < new Date(clientRecord.expiryDate)) {
        return res.status(200).send(JSON.stringify({ 
            id: safeKey, status: "Verified", code: 0, message: "Thành công.", 
            remaining_seconds: Math.floor((new Date(clientRecord.expiryDate) - now) / 1000), data: baseData 
        }));
    }
    return res.status(403).send(JSON.stringify({ id: safeKey, status: "Unverified", code: 400, message: "Lỗi Bản Quyền!", data: baseData }));
}

app.get('/check-auth', (req, res) => { handleCheckAuth(req.query.id || req.query.key, res); });
app.get('/ping', (req, res) => res.send('Heartbeat active'));

app.all('*', (req, res) => {
    if (req.path === '/favicon.ico') return res.status(204).end();
    if (req.path.includes('.')) return sendLocalConfig(req, res);
    const unparsedBody = req.body || {};
    const possibleId = req.query.key || req.query.licenseKey || unparsedBody.licenseKey || req.query.id || req.query.accountId || unparsedBody.id;
    if (possibleId) return handleCheckAuth(possibleId, res);
    sendLocalConfig(req, res);
});

// =========================================================================
// KHỞI ĐỘNG MÁY CHỦ & GIỮ KẾT NỐI CHỐNG NGỦ (ANTI-SLEEP PING)
// =========================================================================
const keepAlive = () => {
    const siteUrl = process.env.RENDER_EXTERNAL_URL || `http://127.0.0.1:${PORT}`;
    if (siteUrl.startsWith('http')) {
        setInterval(() => {
            http.get(`${siteUrl}/ping`, (res) => {}).on('error', () => {});
        }, 5 * 60 * 1000); 
    }
};

app.listen(PORT, () => {
    console.log(`🚀 Mainframe Online tại cổng ${PORT}`);
    keepAlive();
});
