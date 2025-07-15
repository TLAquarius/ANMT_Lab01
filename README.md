# 📖 ĐỒ ÁN 1: ỨNG DỤNG MÔ PHỎNG HỆ THỐNG BẢO MẬT

**Môn học:** An Ninh Máy Tính

---

Kính gửi Thầy,

Chúng em là nhóm sinh viên thực hiện đồ án môn học An Ninh Máy Tính.
Tệp README.md này được soạn thảo với mục đích hướng dẫn Thầy cách thiết lập môi trường, cài đặt các thư viện cần thiết và chạy ứng dụng của chúng em một cách thuận tiện nhất.

---

## 👥 Thông tin nhóm

Dự án được thực hiện bởi nhóm sinh viên:
1. 22127124 - Nguyễn Anh Hoàng
2. 22127392 - Lê Phước Thạnh
3. 22127485 - Nguyễn Minh Tâm

---

## 📜 Mục lục

1. [Yêu cầu hệ thống](#1-yêu-cầu-hệ-thống)
2. [Hướng dẫn cài đặt](#2-hướng-dẫn-cài-đặt)
   - [Bước 1: Thiết lập môi trường Python](#bước-1-thiết-lập-môi-trường-python)
     - [Cách A: Sử dụng Python và venv](#cách-a-sử-dụng-python-và-venv)
     - [Cách B: Sử dụng Anaconda/Miniconda](#cách-b-sử-dụng-anacondaminiconda)
   - [Bước 2: Cài đặt các thư viện](#bước-2-cài-đặt-các-thư-viện)
   - [Bước 3: Chạy ứng dụng](#bước-3-chạy-ứng-dụng)
3. [Cấu trúc thư mục dự án](#3-cấu-trúc-thư-mục-dự-án)
4. [Tổng quan các chức năng chính](#4-tổng-quan-các-chức-năng-chính)
5. [Tài liệu báo cáo](#5-tài-liệu-báo-cáo)

---

## 1. Yêu cầu hệ thống

- **Python:** Phiên bản 3.10 trở lên

---

## 2. Hướng dẫn cài đặt

### Bước 1: Thiết lập môi trường Python

Để đảm bảo các thư viện của dự án không ảnh hưởng đến môi trường Python chung của máy, chúng em khuyến khích việc tạo một môi trường ảo (virtual environment).

#### Cách A: Sử dụng Python và venv

1. Mở Terminal (hoặc Command Prompt/PowerShell trên Windows) tại thư mục gốc của dự án.

2. Tạo môi trường ảo:
   
   **Trên macOS/Linux:**
   ```bash
   python3 -m venv venv
   ```
   
   **Trên Windows:**
   ```bash
   python -m venv venv
   ```
   
   Lệnh này sẽ tạo một thư mục `venv` chứa môi trường Python riêng biệt.

3. Kích hoạt môi trường ảo:
   
   **Trên macOS/Linux:**
   ```bash
   source venv/bin/activate
   ```
   
   **Trên Windows:**
   ```bash
   .\venv\Scripts\activate
   ```
   
   Sau khi kích hoạt, tên môi trường ảo `(venv)` sẽ xuất hiện ở đầu dòng lệnh.

#### Cách B: Sử dụng Anaconda/Miniconda

1. Mở Anaconda Prompt từ Start Menu.
2. Di chuyển đến thư mục gốc của dự án.
3. Tạo một môi trường conda mới với phiên bản Python phù hợp:
   ```bash
   conda create --name anmt python=3.10
   ```
4. Kích hoạt môi trường vừa tạo:
   ```bash
   conda activate anmt
   ```

### Bước 2: Cài đặt các thư viện

Sau khi đã kích hoạt môi trường ảo, tiến hành cài đặt các thư viện cần thiết bằng lệnh sau:

```bash
pip install Pillow pyotp "qrcode[pil]" pyzbar cryptography
```

### Bước 3: Chạy ứng dụng

Sau khi hoàn tất các bước cài đặt, Thầy có thể khởi chạy ứng dụng:

```bash
python main.py
```

Cửa sổ chính của ứng dụng sẽ hiện ra, cho phép thực hiện các chức năng như **Đăng ký**, **Đăng nhập**.

---

## 3. Cấu trúc thư mục dự án

Dự án được tổ chức theo cấu trúc module rõ ràng để dễ dàng quản lý và bảo trì:

```
/
├── .gitignore
├── main.py
├── README.md
├── report/
│   └── ... (Báo cáo đồ án)
├── gui/
│   ├── __init__.py
│   ├── admin_panel.py
│   ├── dashboard_window.py
│   ├── key_status_ui.py
│   ├── login_window.py
│   ├── recovery_window.py
│   └── register_window.py
├── modules/
│   ├── __init__.py
│   ├── admin.py
│   ├── auth.py
│   ├── file_crypto.py
│   ├── file_sign.py
│   ├── key_status.py
│   ├── logger.py
│   ├── mfa.py
│   ├── pubkey_search.py
│   ├── qr_utils.py
│   ├── recovery.py
│   └── rsa_keys.py
└── data/
    ├── security.log
    ├── users.json
    └── ... (Các thư mục/dữ liệu được tạo tự động khi chạy)
```

**Mô tả các thư mục/file chính:**

- **`main.py`**: Điểm khởi đầu của ứng dụng, tạo cửa sổ chính
- **`gui/`**: Chứa các module giao diện người dùng (GUI) được xây dựng bằng Tkinter
- **`modules/`**: Chứa toàn bộ logic xử lý nghiệp vụ của ứng dụng (xác thực, mã hóa, quản lý khóa,...)
- **`data/`**: Thư mục lưu trữ dữ liệu của ứng dụng như thông tin người dùng (`users.json`), nhật ký hệ thống (`security.log`), khóa công khai và các tệp do người dùng tạo ra. Thư mục này sẽ được tự động tạo khi chạy
- **`report/`**: Chứa tài liệu báo cáo của đồ án

---

## 4. Tổng quan các chức năng chính

Ứng dụng mô phỏng một hệ thống bảo mật với các tính năng cốt lõi:

### 🔐 Đăng ký tài khoản
Người dùng cung cấp thông tin cá nhân và passphrase mạnh. Hệ thống sẽ băm passphrase với salt và lưu trữ an toàn.

### 🔑 Đăng nhập & Xác thực đa yếu tố (MFA)
Hỗ trợ xác thực bằng OTP (mô phỏng gửi qua email) hoặc TOTP (qua ứng dụng Google Authenticator). Có cơ chế khóa tài khoản tạm thời sau nhiều lần đăng nhập thất bại.

### 🗝️ Quản lý khóa RSA
Người dùng có thể tạo, gia hạn cặp khóa RSA (2048-bit). Private key được mã hóa bằng AES-256-GCM với key được sinh từ passphrase.

### 📱 Chia sẻ Public Key qua QR Code
Dễ dàng chia sẻ và lưu trữ khóa công khai của người khác.

### 🔒 Mã hóa & Giải mã tệp
Sử dụng mô hình mã hóa Hybrid (AES + RSA) để mã hóa tệp tin gửi cho người khác. Hỗ trợ chia tệp lớn và tùy chọn lưu khóa phiên riêng biệt.

### ✍️ Ký số & Xác minh chữ ký
Cho phép người dùng ký lên tệp tin bằng private key và xác minh chữ ký của người khác bằng public key đã lưu.

### 🔄 Khôi phục tài khoản
Sử dụng mã khôi phục được cấp lúc đăng ký để đặt lại passphrase.

### 👨‍💼 Phân quyền & Quản trị
Hệ thống có vai trò admin và user. Admin có thể xem danh sách người dùng, khóa/mở khóa tài khoản, và xem nhật ký hoạt động của toàn hệ thống.

---

## 5. Tài liệu báo cáo

Toàn bộ tài liệu báo cáo chi tiết, video demo, và các file test liên quan được lưu trữ tại Google Drive:

**[https://drive.google.com/drive/folders/1uGk7LX50IJ7h8fxVRgQEWulPXA4UZLrC?usp=drive_link]**

---

**Cảm ơn Thầy đã dành thời gian để xem xét dự án của chúng em!** 
