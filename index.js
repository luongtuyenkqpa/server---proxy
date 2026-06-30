const express = require('express');
const app = express();
const http = require('http');
const PORT = process.env.PORT || 3000;

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Cơ sở dữ liệu bộ nhớ tạm thời phục vụ thử nghiệm
let keyDatabase = [
    { 
        key: "64KA-MA6H5-YSBS", 
        type: "Gói Cao Cấp", 
        durationHours: 24, 
        status: "Chưa kích hoạt", // Chưa kích hoạt, Đã kích hoạt, Tạm ngừng, Đã khóa
        idGame: "", 
        expiryDate: null 
    }
];
let totalKeysCreated = 14177; 

// Hàm tính toán thời gian chuẩn múi giờ Việt Nam (ICT - UTC+7)
function getVNTime(offsetHours = 0, baseDate = null) {
    const now = baseDate ? new Date(baseDate) : new Date();
    const utc = now.getTime() + (now.getTimezoneOffset() * 60000);
    return new Date(utc + (3600000 * 7) + (3600000 * offsetHours));
}

function formatVNFormat(dateObj) {
    if (!dateObj) return "Chưa kích hoạt";
    const pad = (n) => n.toString().padStart(2, '0');
    return `${pad(dateObj.getDate())}/${pad(dateObj.getMonth() + 1)}/${dateObj.getFullYear()} ${pad(dateObj.getHours())}:${pad(dateObj.getMinutes())}:${pad(dateObj.getSeconds())}`;
}

// 1. Cấu hình tệp cục bộ cho Client đọc dữ liệu cấu hình
app.get('/localconfig.json', (req, res) => {
    res.json({
        "verAddr": `https://${req.get('host')}/`,
        "resetGuest": true
    });
});

// 2. Giao diện trang chủ Kích hoạt Key dành cho người dùng cuối
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
            <a href="/login">Đăng Nhập Quản Trị</a>
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

// Xử lý logic đăng ký nhận thông tin từ Form người dùng
app.post('/activate', (req, res) => {
    const { idGame, licenseKey } = req.body;
    let targetRecord = keyDatabase.find(k => k.key === licenseKey.trim());

    if (!targetRecord) {
        return res.send(`<h3 style="color:#ff4a7d; background:#0b0914; height:100vh; display:flex; justify-content:center; align-items:center; margin:0; font-family:sans-serif;">Lỗi: Mã key xác thực không hợp lệ.</h3>`);
    }
    if (targetRecord.status === "Đã khóa") {
        return res.send(`<h3 style="color:#ff4a7d; background:#0b0914; height:100vh; display:flex; justify-content:center; align-items:center; margin:0; font-family:sans-serif;">Lỗi: Mã key này đã bị khóa vĩnh viễn trên toàn hệ thống.</h3>`);
    }
    if (targetRecord.status === "Tạm ngừng") {
        return res.send(`<h3 style="color:#ffaa00; background:#0b0914; height:100vh; display:flex; justify-content:center; align-items:center; margin:0; font-family:sans-serif;">Thông báo: Mã key này đang tạm thời ngừng hoạt động bởi quản trị viên.</h3>`);
    }
    if (targetRecord.status === "Đã kích hoạt" && targetRecord.idGame !== idGame.trim()) {
        return res.send(`<h3 style="color:#ff4a7d; background:#0b0914; height:100vh; display:flex; justify-content:center; align-items:center; margin:0; font-family:sans-serif;">Lỗi: Mã key này đã được liên kết với một ID khác trước đó.</h3>`);
    }

    const startVN = getVNTime();
    let expiryVN;

    if (targetRecord.expiryDate) {
        expiryVN = new Date(targetRecord.expiryDate);
    } else {
        expiryVN = getVNTime(targetRecord.durationHours);
        targetRecord.expiryDate = expiryVN;
    }

    targetRecord.status = "Đã kích hoạt";
    targetRecord.idGame = idGame.trim();

    res.send(`
    <!DOCTYPE html>
    <html lang="vi">
    <head>
        <meta charset="UTF-8">
        <title>Xác Thực Thành Công</title>
        <style>
            body { background: #0b0914; color: #fff; font-family: sans-serif; display: flex; justify-content: center; align-items: center; height: 100vh; margin: 0; }
            .card { background: #141124; padding: 30px; border-radius: 16px; border: 1px solid #52c41a; width: 400px; box-shadow: 0 4px 20px rgba(0,0,0,0.5); }
            h2 { color: #52c41a; text-align: center; margin-top: 0; }
            .row { background: #0b0914; padding: 12px; margin: 10px 0; border-radius: 8px; font-size: 14px; border-left: 4px solid #8a3ffc; display: flex; justify-content: space-between; }
            .val { font-weight: bold; color: #1890ff; }
        </style>
    </head>
    <body>
        <div class="card">
            <h2>KÍCH HOẠT THÀNH CÔNG</h2>
            <div class="row"><span>ID Game:</span> <span class="val">${idGame}</span></div>
            <div class="row"><span>Thời gian bắt đầu:</span> <span class="val">${formatVNFormat(startVN)}</span></div>
            <div class="row"><span>Thời gian hết hạn:</span> <span class="val">${formatVNFormat(expiryVN)}</span></div>
            <p style="text-align:center; margin-bottom:0;"><a href="/" style="color:#8a3ffc; text-decoration:none; font-size:14px;">Quay lại trang chủ</a></p>
        </div>
    </body>
    </html>
    `);
});

// Trang Đăng nhập Quản trị viên
app.get('/login', (req, res) => {
    res.send(`
    <!DOCTYPE html>
    <html lang="vi">
    <head>
        <meta charset="UTF-8">
        <title>Đăng Nhập Quản Trị</title>
        <style>
            body { background: #0b0914; color: #fff; font-family: sans-serif; display: flex; justify-content: center; align-items: center; height: 100vh; margin: 0; }
            .login-box { background: #141124; padding: 30px; border-radius: 12px; border: 1px solid #2a2444; width: 320px; }
            input { width: 100%; padding: 12px; margin: 10px 0; border-radius: 6px; border: 1px solid #2a2444; background: #0b0914; color: #fff; box-sizing: border-box; }
            button { width: 100%; padding: 12px; background: #8a3ffc; border: none; color: #fff; font-weight: bold; border-radius: 6px; cursor: pointer; }
        </style>
    </head>
    <body>
        <div class="login-box">
            <h3 style="text-align:center; margin-top:0;">ADMIN LOGIN</h3>
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
    const { username, password } = req.body;
    if (username === 'admin' && password === '120510@') {
        res.send(`
            <script>
                localStorage.setItem('admin_token', 'session_verified_120510');
                window.location.href = '/admin';
            </script>
        `);
    } else {
        res.send(`<h3 style="color:red; text-align:center; font-family:sans-serif; margin-top:50px;">Sai tài khoản hoặc mật khẩu!</h3><p style="text-align:center;"><a href="/login">Thử lại</a></p>`);
    }
});

// 3. Hệ thống Web Admin quản lý toàn quyền tạo lập và cấu hình Key
app.get('/admin', (req, res) => {
    let tableRows = keyDatabase.map((k, index) => {
        let statusColor = "#1890ff";
        if (k.status === "Chưa kích hoạt") statusColor = "#797687";
        if (k.status === "Đã kích hoạt") statusColor = "#52c41a";
        if (k.status === "Tạm ngừng") statusColor = "#ffaa00";
        if (k.status === "Đã khóa") statusColor = "#ff4a7d";

        return `
        <tr>
            <td style="color: #fff; font-family: monospace;">${k.key}</td>
            <td><span style="background: rgba(255,255,255,0.05); padding: 4px 8px; border-radius: 4px; font-size: 12px;">${k.type}</span></td>
            <td><span style="color:${statusColor}; font-weight:bold;">${k.status}</span></td>
            <td style="color: #1890ff;">${k.idGame || '---'}</td>
            <td style="font-size: 13px; color: #aaa;">${formatVNFormat(k.expiryDate)}</td>
            <td>
                <div style="display:flex; gap: 5px;">
                    <form action="/admin/action/single" method="POST" style="display:inline;">
                        <input type="hidden" name="index" value="${index}">
                        <select name="actionType" onchange="this.form.submit()" style="width:110px; margin:0; padding:4px;">
                            <option value="">Thao tác...</option>
                            <option value="add_1h">+1 Giờ</option>
                            <option value="add_24h">+24 Giờ</option>
                            <option value="pause">Tạm Ngừng</option>
                            <option value="resume">Bỏ Tạm Ngừng</option>
                            <option value="reset">Reset Key</option>
                            <option value="band">Band Key</option>
                        </select>
                    </form>
                </div>
            </td>
        </tr>
        `;
    }).join('');

    const totalUsed = keyDatabase.filter(k => k.status === "Đã kích hoạt").length;
    const totalUnused = keyDatabase.filter(k => k.status === "Chưa kích hoạt").length;

    res.send(`
    <!DOCTYPE html>
    <html lang="vi">
    <head>
        <meta charset="UTF-8">
        <title>Hệ Thống Quản Lý Bản Quyền</title>
        <script>
            if(localStorage.getItem('admin_token') !== 'session_verified_120510') {
                window.location.href = '/login';
            }
        </script>
        <style>
            body { background: #0b0914; color: #cdcbde; font-family: 'Segoe UI', sans-serif; padding: 30px; margin: 0; }
            .admin-box { max-width: 1100px; margin: 0 auto; background: #141124; border: 1px solid #2a2444; border-radius: 16px; padding: 30px; }
            h1 { font-size: 24px; margin: 0 0 5px 0; color: #fff; }
            .subtitle { color: #797687; font-size: 14px; margin: 0 0 25px 0; }
            .control-panel { background: #1c1832; padding: 20px; border-radius: 12px; margin-bottom: 25px; border: 1px solid #2a2444; }
            label { font-size: 13px; color: #797687; display: block; margin-bottom: 8px; }
            select, input[type="number"] { background: #0b0914; border: 1px solid #2a2444; color: #fff; padding: 10px; border-radius: 8px; width: 220px; margin-right: 10px; }
            .btn-group { display: flex; gap: 10px; flex-wrap: wrap; margin-top: 15px; }
            .btn { padding: 10px 20px; border-radius: 8px; font-weight: bold; cursor: pointer; border: none; font-size: 14px; color: #fff; }
            .btn-blue { background: #1d72b8; }
            .btn-purple { background: #8a3ffc; }
            .btn-danger { background: #ff4a7d; }
            .stats { display: flex; gap: 15px; margin-bottom: 25px; }
            .stat-card { background: #1c1832; border: 1px solid #2a2444; padding: 20px; border-radius: 12px; flex: 1; }
            .stat-title { font-size: 13px; color: #797687; margin-bottom: 5px; }
            .stat-num { font-size: 26px; font-weight: bold; color: #fff; }
            table { width: 100%; border-collapse: collapse; margin-top: 15px; }
            th, td { padding: 14px; text-align: left; border-bottom: 1px solid #2a2444; font-size: 14px; }
            th { color: #797687; font-weight: 500; background: #1c1832; }
        </style>
    </head>
    <body>
        <div class="admin-box">
            <h1>Cấu Hình Bản Quyền License</h1>
            <div class="subtitle">Hệ thống tạo key, phân bổ thời gian và quản lý trạng thái kích hoạt tài khoản trò chơi.</div>
            
            <div class="control-panel">
                <h3 style="color:#fff; margin-top:0;">TÙY CHỌN TẤT CẢ HỆ THỐNG (BULK ACTIONS)</h3>
                <form action="/admin/action/global" method="POST">
                    <label>Thêm thời gian cho TẤT CẢ các key (Giờ)</label>
                    <input type="number" name="hoursToAdd" placeholder="Ví dụ: 24" min="1">
                    <div class="btn-group">
                        <button class="btn btn-purple" type="submit" name="globalAction" value="add_time">Cập nhật toàn bộ giờ</button>
                        <button class="btn btn-blue" type="submit" name="globalAction" value="generate">Tạo key mới</button>
                        <button class="btn btn-danger" type="submit" name="globalAction" value="reset_all">Reset tất cả key</button>
                    </div>
                </form>
            </div>

            <div class="stats">
                <div class="stat-card"><div class="stat-title">Tổng key hệ thống</div><div class="stat-num">${totalKeysCreated}</div></div>
                <div class="stat-card"><div class="stat-title">Đã kích hoạt</div><div class="stat-num" style="color: #52c41a;">${totalUsed}</div></div>
                <div class="stat-card"><div class="stat-title">Chưa kích hoạt (tab)</div><div class="stat-num" style="color: #1890ff;">${totalUnused}</div></div>
            </div>

            <h2 style="font-size:16px; color:#fff; margin: 30px 0 10px 0;">DANH SÁCH LICENSE KEYS</h2>
            <table>
                <thead>
                    <tr>
                        <th>MÃ KEY</th>
                        <th>PHÂN LOẠI</th>
                        <th>TRẠNG THÁI</th>
                        <th>GAME ID</th>
                        <th>THỜI HẠN HẾT HẠN (VN)</th>
                        <th>HÀNH ĐỘNG</th>
                    </tr>
                </thead>
                <tbody>
                    ${tableRows}
                </tbody>
            </table>
        </div>
    </body>
    </html>
    `);
});

// Điều khiển đơn lẻ trên từng dòng key
app.post('/admin/action/single', (req, res) => {
    const { index, actionType } = req.body;
    let idx = parseInt(index);
    if (isNaN(idx) || idx < 0 || idx >= keyDatabase.length) return res.redirect('/admin');

    let item = keyDatabase[idx];

    switch(actionType) {
        case "add_1h":
            if (item.expiryDate) item.expiryDate = getVNTime(1, item.expiryDate);
            break;
        case "add_24h":
            if (item.expiryDate) item.expiryDate = getVNTime(24, item.expiryDate);
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
    }
    res.redirect('/admin');
});

// Xử lý hành động hàng loạt hoặc tạo mới trên Admin
app.post('/admin/action/global', (req, res) => {
    const { globalAction, hoursToAdd } = req.body;

    if (globalAction === "generate") {
        const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
        const segment = () => Array.from({length: 4}, () => chars[Math.floor(Math.random() * chars.length)]).join('');
        const generatedKey = `${segment()}-${segment()}-${segment()}`;

        keyDatabase.unshift({
            key: generatedKey,
            type: "Gói Cao Cấp",
            durationHours: 24, 
            status: "Chưa kích hoạt",
            idGame: "",
            expiryDate: null
        });
        totalKeysCreated++;
    } else if (globalAction === "add_time") {
        let hrs = parseInt(hoursToAdd);
        if (!isNaN(hrs) && hrs > 0) {
            keyDatabase.forEach(k => {
                if (k.expiryDate) {
                    k.expiryDate = getVNTime(hrs, k.expiryDate);
                }
            });
        }
    } else if (globalAction === "reset_all") {
        keyDatabase.forEach(k => {
            k.status = "Chưa kích hoạt";
            k.idGame = "";
            k.expiryDate = null;
        });
    }
    res.redirect('/admin');
});

// 4. API Endpoint kiểm tra trạng thái ID từ thiết bị/overlay game
app.get('/check-auth', (req, res) => {
    const id = req.query.id;
    if (!id) return res.status(400).json({ status: "error" });

    const clientRecord = keyDatabase.find(k => k.idGame === id.trim());
    const now = getVNTime();

    if (clientRecord && clientRecord.status === "Đã kích hoạt" && clientRecord.expiryDate && now < clientRecord.expiryDate) {
        res.json({ id: id, status: "Verified" });
    } else if (clientRecord && clientRecord.status === "Tạm ngừng") {
        res.json({ id: id, status: "Paused" });
    } else if (clientRecord && clientRecord.status === "Đã khóa") {
        res.json({ id: id, status: "Banned" });
    } else {
        res.json({ id: id, status: "Not Verified" });
    }
});

// 5. Hệ thống Tự Động Ping Cao Cấp Duy Trì Tiến Trình Thức Tỉnh (Anti-Sleep)
app.get('/ping', (req, res) => {
    res.send('Heartbeat active');
});

// Cơ chế tự phát tín hiệu HTTP gọi chính mình mỗi 3 phút
setInterval(() => {
    const host = process.env.RENDER_EXTERNAL_URL || `http://localhost:${PORT}`;
    http.get(`${host}/ping`, (resp) => {
        // Luồng giữ kết nối trống để ngăn hệ thống hạ tầng đóng container
    }).on("error", (err) => {
        console.log("Duy trì ping lỗi: " + err.message);
    });
}, 180000); // 180,000 ms = 3 phút

app.listen(PORT, () => {
    console.log(`Server đang hoạt động đồng bộ tại cổng ${PORT}`);
});
