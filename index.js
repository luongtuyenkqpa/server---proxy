const express = require('express');
const app = express();
const PORT = process.env.PORT || 3000;

// Cấu hình để đọc dữ liệu từ form POST gửi lên
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Cơ sở dữ liệu tạm thời (Mô phỏng)
// Trong thực tế, dữ liệu này sẽ bị reset khi Render khởi động lại nếu không dùng Database
let keyDatabase = [
    { key: "64KA-MA6H5-YSBS", type: "Proxy aim body", durationHours: 1, isUsed: false, idGame: "", expiryDate: null }
];
let totalKeysCreated = 14177; // Số lượng mô phỏng theo ảnh

// Hàm lấy thời gian hiện tại theo múi giờ Việt Nam (ICT - UTC+7)
function getVNTime(offsetHours = 0) {
    const now = new Date();
    // Chuyển đổi sang thời gian UTC + offset mong muốn
    const utc = now.getTime() + (now.getTimezoneOffset() * 60000);
    const vnTime = new Date(utc + (3600000 * 7) + (3600000 * offsetHours));
    return vnTime;
}

// Định dạng ngày giờ hiển thị: DD/MM/YYYY HH:mm:ss
function formatVNFormat(dateObj) {
    if (!dateObj) return "Chưa xác định";
    const pad = (n) => n.toString().padStart(2, '0');
    return `${pad(dateObj.getDate())}/${pad(dateObj.getMonth() + 1)}/${dateObj.getFullYear()} ${pad(dateObj.getHours())}:${pad(dateObj.getMinutes())}:${pad(dateObj.getSeconds())}`;
}

// 1. API Endpoint: Trả về file localconfig.json cấu hình chuyển hướng cho game
app.get('/localconfig.json', (req, res) => {
    res.json({
        "verAddr": `https://${req.get('host')}/`,
        "resetGuest": true
    });
});

// 2. Giao diện trang chủ dành cho người dùng: Xác thực & Kích hoạt Key + ID
app.get('/', (req, res) => {
    res.send(`
    <!DOCTYPE html>
    <html lang="vi">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Hệ Thống Xác Thực Cấu Hình</title>
        <style>
            body { background: #0f0c1b; color: #fff; font-family: sans-serif; display: flex; justify-content: center; align-items: center; height: 100vh; margin: 0; }
            .container { background: #1a162b; padding: 30px; border-radius: 12px; box-shadow: 0 4px 15px rgba(0,0,0,0.5); width: 350px; text-align: center; border: 1px solid #3d2f5c; }
            h2 { color: #ff4a7d; margin-bottom: 5px; }
            p { color: #aaa; font-size: 14px; margin-bottom: 20px; }
            input { width: 100%; padding: 12px; margin: 8px 0; border-radius: 6px; border: 1px solid #3d2f5c; background: #100d1e; color: #fff; box-sizing: border-box; }
            button { width: 100%; padding: 12px; background: #7f00ff; border: none; color: #fff; font-size: 16px; font-weight: bold; border-radius: 6px; cursor: pointer; margin-top: 10px; }
            button:hover { background: #6600cc; }
            .alert { background: rgba(255, 74, 125, 0.1); border: 1px solid #ff4a7d; padding: 10px; border-radius: 6px; font-size: 13px; margin-bottom: 15px; }
        </style>
    </head>
    <body>
        <div class="container">
            <h2>Hệ Thống Kích Hoạt</h2>
            <div class="alert">Vui lòng nhập ID Game và mã Key bản quyền chính xác để thực hiện xác thực trạng thái tài khoản.</div>
            <form action="/activate" method="POST">
                <input type="text" name="idGame" placeholder="Nhập ID Game cần kích hoạt" required>
                <input type="text" name="licenseKey" placeholder="Nhập Mã Key Bản Quyền" required>
                <button type="submit">KÍCH HOẠT NGAY</button>
            </form>
        </div>
    </body>
    </html>
    `);
});

// Xử lý logic Form kích hoạt
app.post('/activate', (req, res) => {
    const { idGame, licenseKey } = req.body;
    
    // Tìm kiếm key trong cơ sở dữ liệu
    let keyInfo = keyDatabase.find(k => k.key === licenseKey.trim());

    if (!keyInfo) {
        return res.send(`<h2 style="color:red; text-align:center; margin-top:50px;">Kích hoạt thất bại: Mã key không tồn tại trong hệ thống!</h2><p style="text-align:center;"><a href="/">Quay lại</a></p>`);
    }
    if (keyInfo.isUsed) {
        return res.send(`<h2 style="color:orange; text-align:center; margin-top:50px;">Key này đã được sử dụng cho ID khác!</h2><p style="text-align:center;"><a href="/">Quay lại</a></p>`);
    }

    // Tiến hành kích hoạt và thiết lập thời gian
    const startTime = getVNTime();
    const expiryTime = getVNTime(keyInfo.durationHours);

    keyInfo.isUsed = true;
    keyInfo.idGame = idGame.trim();
    keyInfo.expiryDate = expiryTime;

    res.send(`
    <!DOCTYPE html>
    <html lang="vi">
    <head>
        <meta charset="UTF-8">
        <title>Kích Hoạt Thành Công</title>
        <style>
            body { background: #0f0c1b; color: #fff; font-family: sans-serif; display: flex; justify-content: center; align-items: center; height: 100vh; margin: 0; }
            .success-card { background: #1a162b; padding: 30px; border-radius: 12px; border: 1px solid #00ffcc; text-align: center; width: 400px; }
            h2 { color: #00ffcc; }
            .info-row { text-align: left; background: #100d1e; padding: 12px; margin: 8px 0; border-radius: 6px; font-size: 14px; border-left: 4px solid #7f00ff; }
            span { font-weight: bold; color: #ff4a7d; }
        </style>
    </head>
    <body>
        <div class="success-card">
            <h2>KÍCH HOẠT THÀNH CÔNG!</h2>
            <div class="info-row">ID Thiết Bị/Game: <span>${idGame}</span></div>
            <div class="info-row">Thời gian bắt đầu: <span>${formatVNFormat(startTime)} (Giờ VN)</span></div>
            <div class="info-row">Thời gian hết hạn: <span>${formatVNFormat(expiryTime)} (Giờ VN)</span></div>
            <p><a href="/" style="color: #00ffcc; text-decoration: none;">Về Trang Chủ</a></p>
        </div>
    </body>
    </html>
    `);
});

// 3. Giao diện Quản trị Web Admin (Được đồng bộ kiểu dáng như hình ảnh Zalo mẫu)
app.get('/admin', (req, res) => {
    const totalUsed = keyDatabase.filter(k => k.isUsed).length;
    const totalUnused = keyDatabase.filter(k => !k.isUsed).length + (totalKeysCreated - keyDatabase.length);

    let rowsHTML = keyDatabase.map(k => `
        <tr>
            <td>${k.key}</td>
            <td>${k.type}</td>
            <td>${k.isUsed ? '<span style="color:#ff4a7d">Đã dùng</span>' : '<span style="color:#00ffcc">Chưa dùng</span>'}</td>
            <td>${k.idGame || '---'}</td>
        </tr>
    `).join('');

    res.send(`
    <!DOCTYPE html>
    <html lang="vi">
    <head>
        <meta charset="UTF-8">
        <title>Hệ Thống Quản Lý Bản Quyền Proxy</title>
        <style>
            body { background: #0b0914; color: #e2e1e6; font-family: sans-serif; padding: 20px; margin: 0; }
            .header-panel { background: linear-gradient(135deg, #181528, #110d1f); padding: 20px; border-radius: 12px; margin-bottom: 20px; }
            h1 { font-size: 24px; margin: 0 0 5px 0; color: #fff; }
            .admin-container { background: #141124; border: 1px solid #2a2444; border-radius: 16px; padding: 25px; max-width: 900px; margin: 0 auto; }
            .btn { background: #1d72b8; border: none; color: white; padding: 10px 20px; border-radius: 8px; font-weight: bold; cursor: pointer; }
            .btn-purple { background: #8a3ffc; }
            .stat-box { background: #1c1832; padding: 15px; border-radius: 8px; flex: 1; margin: 5px; }
            .stat-container { display: flex; justify-content: space-between; margin: 20px 0; }
            table { width: 100%; border-collapse: collapse; margin-top: 20px; }
            th, td { padding: 12px; text-align: left; border-bottom: 1px solid #2a2444; }
            th { background: #1c1832; color: #aaa; }
            .form-section { background: #1c1832; padding: 15px; border-radius: 8px; margin-bottom: 20px; }
            select, input[type="text"] { background: #0b0914; border: 1px solid #2a2444; color: #white; padding: 8px; border-radius: 4px; margin-right: 10px; color: #fff; }
        </style>
    </head>
    <body>
        <div class="admin-container">
            <div class="header-panel">
                <h1>Tạo Key Proxy</h1>
                <p style="color: #797687; margin:0;">Tạo key, token reset, và danh sách license theo từng loại proxy.</p>
            </div>

            <div class="form-section">
                <label>Loại proxy: </label>
                <select id="proxyType">
                    <option>Proxy aim body</option>
                    <option>Proxy aim lock</option>
                </select>
                <br><br>
                <form action="/admin/generate" method="POST" style="display:inline;">
                    <button class="btn" type="submit">Tạo key</button>
                </form>
                <button class="btn btn-purple">Sao chép key</button>
                <button class="btn">Tạo token reset</button>
                <button class="btn">Reset all key</button>
            </div>

            <div class="stat-container">
                <div class="stat-box">Tổng key (tab này)<br><b style="font-size:24px;">${totalKeysCreated}</b></div>
                <div class="stat-box">Đã dùng<br><b style="font-size:24px; color:#52c41a;">${totalUsed}</b></div>
                <div class="stat-box">Chưa dùng<br><b style="font-size:24px; color:#1890ff;">${totalUnused}</b></div>
            </div>

            <h3>DANH SÁCH LICENSE KEYS</h3>
            <table>
                <thead>
                    <tr>
                        <th>KEY</th>
                        <th>LOẠI</th>
                        <th>TRẠNG THÁI</th>
                        <th>DEVICE ID / GAME ID</th>
                    </tr>
                </thead>
                <tbody>
                    ${rowsHTML}
                </tbody>
            </table>
        </div>
    </body>
    </html>
    `);
});

// Xử lý tạo key mới từ giao diện Admin
app.post('/admin/generate', (req, res) => {
    // Thuật toán sinh chuỗi key ngẫu nhiên dạng: XXXX-XXXX-XXXX
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
    const genPart = () => Array.from({length: 4}, () => chars[Math.floor(Math.random() * chars.length)]).join('');
    const newKey = `${genPart()}-${genPart()}-${genPart()}`;

    keyDatabase.unshift({
        key: newKey,
        type: "Proxy aim body",
        durationHours: 24, // Thời hạn mặc định cho key mới tạo là 24 giờ
        isUsed: false,
        idGame: "",
        expiryDate: null
    });
    totalKeysCreated++;
    res.redirect('/admin');
});

// 4. API Endpoint kiểm tra trạng thái ID trực tiếp từ Client Overlay game
app.get('/check-auth', (req, res) => {
    const id = req.query.id;
    if (!id) return res.status(400).json({ status: "error" });

    // Kiểm tra xem ID có khớp với thiết bị nào đã kích hoạt không
    const record = keyDatabase.find(k => k.idGame === id.trim() && k.isUsed);
    const currentTime = getVNTime();

    if (record && record.expiryDate && currentTime < record.expiryDate) {
        res.json({ id: id, status: "Verified" });
    } else {
        res.json({ id: id, status: "Not Verified" });
    }
});

// 5. API nhận gói ping duy trì trạng thái thức tỉnh
app.get('/ping', (req, res) => {
    res.send('pong');
});

app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});
