# KeyVault

Hệ thống lưu trữ key bí mật. Key được xuất ra qua API, nhưng bên nhận chỉ giải mã được khi có **đủ cả 3 yếu tố**:
API key, **mã OTP từ Google Authenticator** và **private key X25519** của chính họ.

> **Bên nhận cần lấy key?** Xem [HUONG_DAN_LAY_KEY.md](HUONG_DAN_LAY_KEY.md).

## Luồng hoạt động

```
Bên nhận                                   KeyVault
  │ 1. POST /api/v1/exports {key_id}  ───▶  kiểm tra quyền, sinh DEK_e tạm,
  │ ◀── ciphertext C (chưa giải mã được)    C = AES-GCM(DEK_e, key), TTL 5 phút
  │ 2. POST /api/v1/exports/{id}/unlock     kiểm tra OTP (chống replay, giới hạn số lần thử)
  │    {otp}                         ───▶   wrap DEK_e bằng public key bên nhận
  │ ◀── wrapped_key (dùng 1 lần)            xóa DEK_e khỏi server
  │ 3. private key → DEK_e → giải mã C
```

- Lưu trữ: envelope encryption. Mỗi key có DEK riêng, DEK được wrap bằng KEK (`KV_MASTER_KEY`). TOTP secret cũng được mã hóa.
- Mỗi mã OTP chỉ dùng được 1 lần. Sai 3 lần trên một export thì export bị hủy. Sai 5 lần liên tiếp thì bên nhận bị khóa 15 phút.
- Mọi thao tác (đăng nhập, thêm key, cấp quyền, export, unlock, lỗi) đều được ghi vào audit log.

## Chạy server

```bash
docker compose build
docker compose run --rm keyvault python -m app.manage gen-secrets > .env
chmod 600 .env
docker compose run --rm keyvault python -m app.manage create-admin admin   # quét QR bằng Google Authenticator
docker compose up -d
```

Dashboard: `https://<domain>/dashboard`. API docs: `/api/docs`.

> Cookie phiên mặc định chỉ gửi qua HTTPS. Khi thử nghiệm qua `http://localhost:8000`, thêm `KV_COOKIE_SECURE=false` vào `.env`.
> Khi triển khai thật, đặt server sau reverse proxy có TLS (nginx/Caddy), rồi sửa `FORWARDED_ALLOW_IPS` trong `docker-compose.yml` để log ghi đúng IP thật của client.

## Dashboard

| Trang | Chức năng |
|---|---|
| Tổng quan | Thống kê, các lượt lấy key gần đây, cảnh báo (OTP sai, API key sai...) |
| Keys | Thêm key (nhập text/hex/base64, hoặc sinh ngẫu nhiên), cấp/thu quyền cho bên nhận, vô hiệu hóa key, xem lịch sử ai đã lấy key |
| Bên nhận | Thêm bên nhận (cấp API key + QR Google Authenticator), kích hoạt, cấp lại API key/OTP khi mất máy, gỡ khóa tạm, vô hiệu hóa |
| Lịch sử lấy key | Ai lấy key nào, khi nào, từ IP nào, trạng thái (Đã lấy / Chờ / Hết hạn / Thất bại). Lọc được theo bên nhận, key, trạng thái |
| Audit log | Toàn bộ sự kiện, có thể chỉ lọc ra các sự kiện thất bại |

Giá trị key **không bao giờ hiển thị lại** trên dashboard. Để nhận diện key, dùng cột fingerprint (HMAC).

## Quy trình thêm một bên nhận

1. Bên nhận chạy `python client/kvclient.py keygen --out recipient.key --encrypt` và gửi public key cho admin.
2. Admin vào Dashboard → Bên nhận → Thêm. Màn hình hiển thị API key và QR **một lần duy nhất**.
3. Bên nhận quét QR bằng Google Authenticator. Admin nhập mã OTP đầu tiên của bên nhận để kích hoạt.
4. Admin vào Dashboard → Keys → chọn key → tick bên nhận → Lưu quyền.

## Yêu cầu truy cập (API public)

Người ngoài có thể tự xin quyền mà không cần tài khoản. Admin duyệt hoặc từ chối trên dashboard, ở trang **Yêu cầu truy cập**.

| Endpoint | Xác thực | Mô tả |
|---|---|---|
| `POST /api/v1/access-requests` | không (giới hạn 5 lần/giờ/IP) | Gửi `name, contact, organization, reason, requested_keys, public_key?`, nhận `request_id` và `claim_token` |
| `GET /api/v1/access-requests/{id}` | `X-Claim-Token` | Xem trạng thái và ghi chú của admin |
| `POST /api/v1/access-requests/{id}/claim` | `X-Claim-Token` | Sau khi được duyệt: nhận **một lần duy nhất** API key, TOTP secret và private key (nếu server sinh) |
| `POST /api/v1/access-requests/{id}/activate` | `X-Claim-Token` | Gửi `{"otp"}` để xác nhận đã thêm vào Google Authenticator |

- Nếu yêu cầu **không kèm `public_key`**, server sinh cặp khóa X25519 lúc claim. Private key chỉ được trả về một lần và **server không lưu lại**.
- Nếu người xin quyền muốn an toàn hơn, họ tự tạo khóa (`kvclient.py keygen`) và gửi kèm `public_key`. Khi đó private key không bao giờ đi qua mạng.
- Hạn claim mặc định là 7 ngày sau khi duyệt (`KV_CLAIM_TTL_HOURS`). Nếu mất thông tin, admin vào trang bên nhận và bấm "Cấp lại".

```bash
python kvclient.py request --server URL --name partner-abc --contact dev@partner.vn --reason "..."   # lưu kv-request.json
python kvclient.py status
python kvclient.py claim        # khi đã được duyệt: lưu recipient.key, hiện QR/secret, hỏi OTP để kích hoạt
```

## Client cho bên nhận

```bash
pip install cryptography            # Python 3.9+
export KV_SERVER=https://vault.example.com KV_API_KEY=kv_xxx
python kvclient.py keys                                       # danh sách key được cấp quyền
python kvclient.py fetch --key-id <id> --out key.bin          # chương trình sẽ hỏi mã OTP
python kvclient.py fetch --key-id <id> --format base64        # in key ra stdout
```

Mỗi mã OTP chỉ dùng được một lần. Muốn lấy 2 key liên tiếp thì phải chờ mã kế tiếp (30 giây).

## Cấu hình (`.env`)

| Biến | Mặc định | Ý nghĩa |
|---|---|---|
| `KV_MASTER_KEY` | (bắt buộc) | KEK, base64 của 32 byte. **Mất biến này là mất toàn bộ key.** Cần backup an toàn |
| `KV_SESSION_SECRET` | (bắt buộc) | Khóa ký cookie phiên |
| `DATABASE_URL` | SQLite `/data/keyvault.db` | Có thể dùng `postgresql+psycopg://...` |
| `KV_EXPORT_TTL` | 300 | Thời gian (giây) để nhập OTP sau khi export |
| `KV_EXPORT_MAX_ATTEMPTS` | 3 | Số lần sai OTP cho phép trên mỗi export |
| `KV_MAX_OTP_FAILURES` / `KV_LOCKOUT_SECONDS` | 5 / 900 | Ngưỡng khóa tạm |
| `KV_DISPLAY_TZ` | Asia/Ho_Chi_Minh | Múi giờ hiển thị trên dashboard |

## Chạy test

```bash
docker run --rm -u root -v "$PWD":/src -w /src keyvault:latest \
  sh -c "pip install -q pytest httpx && python -m pytest -q tests"
```

## Hướng nâng cấp cho production

- Thay `KeyEncryptionKey` (`app/crypto.py`) bằng adapter KMS/HSM với cùng interface `wrap/unwrap/fingerprint`.
- Dùng PostgreSQL thay SQLite khi có nhiều instance chạy song song (row lock khi unlock chỉ có hiệu lực trên PostgreSQL).
- Đẩy audit log sang SIEM, và cảnh báo khi có lượt OTP sai hoặc tài khoản bị khóa.
- Đồng bộ giờ server bằng NTP, vì TOTP phụ thuộc vào thời gian.
