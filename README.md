# Umber Desk 12 — Authorization fixture server

Server Flask nhỏ (~260 dòng) tái hiện 5 lỗi Authorization thường gặp trong SaaS multi-tenant: ownership, property-level authorization, tenant scope, parent-child relationship và indirect access path. Có một flag để chuyển giữa bản có lỗi và bản đã sửa, dùng để so sánh trực tiếp hành vi trước/sau khi fix.

## 5 lỗi được tái hiện

| Finding | Boundary | Endpoint |
|---|---|---|
| 01 | Ownership | `GET /api/v1/notes/<note_id>` |
| 02 | Property-level authorization | `PATCH /api/v1/notes/<note_id>` |
| 03 | Tenant scope | `GET /api/v1/manager/cases/<case_id>` |
| 04 | Parent-child relationship | `GET /api/v1/orgs/<org_id>/cases/<case_id>/evidence/<evidence_id>` |
| 05 | Indirect access path | `POST /api/v1/exports` → worker → `GET /api/v1/exports/<job_id>/download` |

## Cài đặt và chạy

```bash
pip install flask --break-system-packages
python app.py
```

Server chạy tại `http://127.0.0.1:5000`. Terminal sẽ in ra mode hiện tại (`VULNERABLE` hoặc `FIXED`).

## Tài khoản test

Toàn bộ user dùng chung mật khẩu `Secret@123`.

| User | Email | Role | Organization |
|---|---|---|---|
| Emma Carter | emma.carter@meldran.test | Owner | org_01 — Meldran Biomedical Works |
| Daniel Reed | daniel.reed@meldran.test | Manager | org_01 — Meldran Biomedical Works |
| Ben Miller | ben.miller@meldran.test | Analyst | org_01 — Meldran Biomedical Works |
| Alex Turner | alex.turner@meldran.test | Analyst | org_01 — Meldran Biomedical Works |
| Maya Collins | maya.collins@ternwick.test | Owner | org_02 — Ternwick Transit Cooperative |
| Leo Foster | leo.foster@ternwick.test | Analyst | org_02 — Ternwick Transit Cooperative |

Login qua `POST /api/v1/session` với `email` và `password`, server trả về session cookie dùng cho các request sau.

## Chuyển giữa vulnerable và fixed build

`VULNERABLE_MODE` là một hằng số ở đầu `app.py`:

```python
VULNERABLE_MODE = True   # tái hiện 5 lỗi
VULNERABLE_MODE = False  # bản đã sửa
```

Đây là hằng số đọc lúc import module, nên sau khi đổi giá trị cần **restart server** (`python app.py`) để áp dụng — không thể chuyển khi server đang chạy.

## Reset dữ liệu

Server lưu dữ liệu trong memory. Restart sẽ tự seed lại từ đầu. Muốn reset mà không cần restart:

```bash
curl -X POST http://127.0.0.1:5000/api/v1/_reset
```

## Giới hạn cố ý

Vài chỗ được đơn giản hóa có chủ đích, không phải thiếu sót:

- Lưu dữ liệu trong memory (dict), không dùng database thật.
- Session là chuỗi cố định map sẵn với 6 user, không phải JWT/bearer token thật.
- Export "worker" chạy đồng bộ ngay trong request thay vì qua queue — logic authorization giống hệt worker bất đồng bộ thật, chỉ đơn giản hóa phần transport.
- Chỉ chạy HTTP/1.1.

## Đọc thêm

Phân tích đầy đủ về root cause và cách sửa từng lỗi: **[Kiểm thử Authorization trong SaaS multi-tenant: Case study 5 lỗ hổng](https://idkwhy07.github.io/posts/authorization-case-study/)**.