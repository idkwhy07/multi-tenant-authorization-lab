# multi-tenant-authorization-lab

## Đây là gì?

Một server Flask nhỏ, dữ liệu lưu trong RAM, tái hiện lại 5 lỗi phân quyền (F-01 → F-05) trong một ứng dụng SaaS multi-tenant hư cấu tên "Umber Desk 12" — được mô tả trong bài viết ["One Authorization Assessment, Five Failures"](LINK_BÀI_VIẾT_CỦA_BẠN).

> Umber Desk 12 là ứng dụng hư cấu. Repo này không phải sản phẩm thật, chỉ tồn tại để phục vụ mục đích minh họa bên dưới.

## Để làm gì?

Bài viết mô tả các HTTP request/response minh họa cho từng lỗi. Thay vì viết tay các ví dụ đó, repo này là một server thật — chạy lên là có thể tự tay gửi request bằng curl/Burp và nhận về đúng response như trong bài, thay vì phải tin vào ví dụ được viết sẵn.

## Công nghệ

- **Python 3.11+** và **Flask** — toàn bộ chỉ 1 file `app.py`
- Không database — dữ liệu là dict Python trong RAM, mất khi restart server
- Không JWT thật — session là cookie cố định, map sẵn tới 6 user dựng sẵn

## Cài đặt

```bash
pip install flask
python app.py
```

Server chạy ở `http://127.0.0.1:5000`, mặc định ở chế độ **có lỗi** (`VULNERABLE_MODE = True` trong `app.py`).

## Sử dụng

**1. Đăng nhập** để lấy session cookie (danh sách email/mật khẩu ở biến `USERS` đầu file):

```bash
curl -X POST http://127.0.0.1:5000/api/v1/session \
  -H "Content-Type: application/json" \
  -d '{"email":"ben.miller@meldran.test","password":"fixture-password"}'
```

**2. Gửi request kèm cookie** trả về ở bước 1:

```bash
curl -i http://127.0.0.1:5000/api/v1/notes/note_02 \
  -H "Cookie: umberdesk12_session=sess_bm_1"
```

**3. Đối chiếu với 5 endpoint tương ứng 5 lỗi:**

| Lỗi | Endpoint | Vấn đề |
|---|---|---|
| F-01 | `GET /api/v1/notes/{id}` | Kiểm tra membership, không kiểm tra ownership |
| F-02 | `PATCH /api/v1/notes/{id}` | Mass assignment — `review_status` không được lọc |
| F-03 | `GET /api/v1/manager/cases/{id}` | Kiểm tra role, không kiểm tra tenant |
| F-04 | `GET /api/v1/orgs/{org}/cases/{case}/evidence/{id}` | Không kiểm tra quan hệ evidence↔case |
| F-05 | `POST /api/v1/exports` | Worker không xác thực lại nguồn dữ liệu |

**4. Xem bản đã sửa:** đổi `VULNERABLE_MODE = False` trong `app.py`, restart, chạy lại request ở bước 2 — sẽ ra kết quả khớp cột "After repair" trong bài viết.

**5. Reset dữ liệu** không cần restart:
```bash
curl -X POST http://127.0.0.1:5000/api/v1/_reset
```