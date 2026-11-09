# Hướng dẫn lấy key từ KeyVault (dành cho bên nhận)

Tài liệu này dành cho người hoặc hệ thống **cần lấy key** từ KeyVault. Phần cài đặt và quản trị server nằm trong [README.md](README.md).

## Tổng quan

Để lấy được một key, bạn cần đủ **3 thứ**:

| Thứ cần có | Là gì | Giữ ở đâu |
|---|---|---|
| **API key** (`kv_...`) | Định danh bạn khi gọi API | Biến môi trường / secret manager |
| **Private key** (`recipient.key`) | Dùng để giải mã key nhận về | Máy của bạn, quyền 600, **không gửi cho ai** |
| **Google Authenticator** | Sinh mã OTP 6 số, đổi mỗi 30 giây | Điện thoại của người phụ trách |

Mỗi lần lấy key diễn ra theo 2 bước:

```
1. POST /api/v1/exports               → nhận bản mã của key (chưa giải mã được)
2. POST /api/v1/exports/{id}/unlock   → gửi mã OTP, nhận khóa giải mã (đã mã hóa bằng public key của bạn)
3. Giải mã tại máy bạn bằng private key
```

Nếu lộ API key, kẻ gian vẫn không lấy được key vì thiếu OTP và private key. Nếu lộ bản mã, cũng không giải mã được.

---

## Phần 1: Đăng ký (làm một lần)

Có 2 cách. Hãy hỏi quản trị viên xem bạn dùng cách nào.

### Cách A: Tự gửi yêu cầu qua API (không cần liên hệ trước)

Chuẩn bị client: cần Python 3.9+ và chạy `pip install cryptography qrcode`, rồi tải file [`client/kvclient.py`](client/kvclient.py).

```bash
export KV_SERVER=https://vault.example.com      # địa chỉ do quản trị viên cung cấp

# 1. Gửi yêu cầu
python kvclient.py request --name "partner-abc" --contact "dev@partner.vn" \
  --organization "Partner ABC" --reason "Tích hợp thanh toán" --requested-keys "payment-hmac"
#    -> tạo file kv-request.json chứa claim token. GIỮ BÍ MẬT file này.

# 2. Kiểm tra trạng thái (chờ quản trị viên duyệt)
python kvclient.py status

# 3. Khi đã được duyệt: nhận thông tin và kích hoạt
python kvclient.py claim
```

Lệnh `claim` sẽ:
- lưu private key do server sinh vào `recipient.key` (server **không** giữ bản sao),
- hiện mã QR. Bạn mở Google Authenticator, chọn **+**, rồi **Quét mã QR**. Nếu không quét được, chọn **Nhập khóa thiết lập** và dán secret được in ra,
- in API key (đồng thời lưu vào `kv-request.json`),
- hỏi mã OTP để kích hoạt.

> **Cách an toàn hơn:** tự tạo cặp khóa để private key không bao giờ đi qua mạng:
> ```bash
> python kvclient.py keygen --out recipient.key --encrypt
> python kvclient.py request --own-key recipient.key --name ... --contact ... --reason ...
> ```

Thông tin chỉ nhận được **một lần**, và phải nhận trong vòng **7 ngày** sau khi được duyệt. Nếu làm mất, hãy liên hệ quản trị viên để được cấp lại.

### Cách B: Quản trị viên đăng ký giúp

```bash
python kvclient.py keygen --out recipient.key --encrypt
# -> in ra public key (một chuỗi base64). Gửi chuỗi này cho quản trị viên.
```

Quản trị viên sẽ gửi lại cho bạn **API key** và **mã QR** (qua kênh an toàn). Bạn quét QR bằng Google Authenticator, rồi đọc mã 6 số cho quản trị viên để kích hoạt.

---

## Phần 2: Lấy key

### Dùng kvclient (khuyến nghị)

```bash
export KV_SERVER=https://vault.example.com
export KV_API_KEY=kv_xxxxxxxxxxxxxxxx

# Xem các key bạn được cấp quyền
python kvclient.py keys
# e504943f45b9408f9d7ba6b973bd8e6f  payment-hmac   32 B  fp=722c2d3c6bb49028

# Lấy key: chương trình sẽ hỏi mã OTP
python kvclient.py fetch --key-id e504943f45b9408f9d7ba6b973bd8e6f --priv recipient.key --out payment.key
```

Các tùy chọn đầu ra:

| Tùy chọn | Kết quả |
|---|---|
| `--out file` | Ghi ra file với quyền 600 (khuyến nghị) |
| `--format base64` / `--format hex` | In ra màn hình dạng base64 / hex |
| (không có) | In nguyên bản ra stdout |

Dùng trong script tự động: truyền `--otp 123456` thay vì để chương trình hỏi.

### Dùng curl

```bash
S=https://vault.example.com
API_KEY=kv_xxxxxxxxxxxxxxxx
KEY_ID=e504943f45b9408f9d7ba6b973bd8e6f

# Danh sách key được cấp
curl -s $S/api/v1/keys -H "X-API-Key: $API_KEY" | jq

# Bước 1: xin export
curl -s -X POST $S/api/v1/exports -H "X-API-Key: $API_KEY" \
  -H 'Content-Type: application/json' -d "{\"key_id\":\"$KEY_ID\"}" > export.json
EID=$(jq -r .export_id export.json)

# Bước 2: mở khóa bằng OTP (trong vòng 5 phút)
curl -s -X POST $S/api/v1/exports/$EID/unlock -H "X-API-Key: $API_KEY" \
  -H 'Content-Type: application/json' -d '{"otp":"123456"}' > unlock.json
```

curl chỉ lấy được dữ liệu đã mã hóa. Bước giải mã phải làm bằng code, xem phần dưới.

### Tự tích hợp bằng ngôn ngữ khác

Thuật toán dùng ở đây đều là chuẩn phổ biến (X25519, HKDF-SHA256, AES-256-GCM), có sẵn trong Java, Node.js, Go, .NET, PHP… Cách giải mã như sau:

```
aad      = utf8(export.aad)                       # "kv-export-v1|<export_id>|<key_id>|<recipient_id>"
wrapped  = base64decode(unlock.wrapped_key)
eph_pub  = wrapped[0:32]
shared   = X25519(my_private_key, eph_pub)
kek      = HKDF-SHA256(ikm=shared, salt=none, length=32,
                       info="keyvault-export-wrap-v1" || eph_pub || my_public_key_raw32)
dek      = AES-256-GCM-Decrypt(key=kek, nonce=wrapped[32:44], ciphertext+tag=wrapped[44:], aad=aad)

ct       = base64decode(export.ciphertext)
KEY      = AES-256-GCM-Decrypt(key=dek, nonce=ct[0:12], ciphertext+tag=ct[12:], aad=aad)
```

Ví dụ Python tối thiểu:

```python
import base64, json
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

e, u = json.load(open("export.json")), json.load(open("unlock.json"))
priv = serialization.load_pem_private_key(open("recipient.key", "rb").read(), None)
my_pub = priv.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
aad = e["aad"].encode()

w = base64.b64decode(u["wrapped_key"])
shared = priv.exchange(X25519PublicKey.from_public_bytes(w[:32]))
kek = HKDF(hashes.SHA256(), 32, None, b"keyvault-export-wrap-v1" + w[:32] + my_pub).derive(shared)
dek = AESGCM(kek).decrypt(w[32:44], w[44:], aad)

ct = base64.b64decode(e["ciphertext"])
print(AESGCM(dek).decrypt(ct[:12], ct[12:], aad))
```

Đặc tả API đầy đủ (OpenAPI): `https://vault.example.com/api/docs`.

---

## Lưu ý quan trọng

- **Mỗi mã OTP chỉ dùng được một lần.** Muốn lấy 2 key liên tiếp, bạn phải chờ mã kế tiếp (khoảng 30 giây).
- Mã OTP của bạn **khác** mã của quản trị viên hay của bên nhận khác. Nếu trên điện thoại có nhiều mục `KeyVault`, hãy chọn đúng mục mang tên bạn.
- Sau bước 1 (export) bạn có **5 phút** để nhập OTP. Quá hạn thì phải export lại.
- Mọi lượt lấy key đều được ghi lại (ai, key nào, lúc nào, từ IP nào), và quản trị viên xem được trên dashboard.
- Không commit `recipient.key`, `kv-request.json` hay API key lên git.
- Giờ hệ thống phải chính xác (bật NTP), nếu không mã OTP sẽ bị báo sai.

## Xử lý lỗi

| Mã lỗi | Thông báo | Nguyên nhân / cách xử lý |
|---|---|---|
| 401 | API key không hợp lệ | Sai `KV_API_KEY`, hoặc đã được cấp lại API key mới |
| 401 | OTP không hợp lệ | Sai mã, dùng lại mã cũ, chọn nhầm mục trong Authenticator, hoặc giờ điện thoại bị lệch |
| 401 | Export đã bị hủy do sai quá số lần cho phép | Sai OTP 3 lần cho cùng một export. Hãy export lại |
| 403 | Bên nhận đang ở trạng thái 'pending' | Chưa kích hoạt OTP. Chạy `kvclient.py activate`, hoặc liên hệ quản trị viên |
| 403 | Bên nhận đang ở trạng thái 'disabled' | Đã bị vô hiệu hóa. Liên hệ quản trị viên |
| 404 | Key không tồn tại hoặc bạn không được cấp quyền | Sai `key_id`, chưa được cấp quyền, hoặc key đã bị vô hiệu |
| 409 | Yêu cầu chưa được duyệt | Chờ quản trị viên duyệt (`kvclient.py status`) |
| 409 | Thông tin đã được nhận trước đó | Claim chỉ dùng được một lần. Liên hệ quản trị viên để được cấp lại |
| 410 | Export đã hết hạn | Quá 5 phút kể từ bước export. Hãy export lại |
| 429 | Tài khoản đang bị tạm khóa | Sai OTP 5 lần liên tiếp. Chờ 15 phút, hoặc nhờ quản trị viên gỡ khóa |
| 429 | Quá nhiều yêu cầu | Gửi quá nhiều yêu cầu truy cập từ một IP. Thử lại sau 1 giờ |
| — | `Private key không phải X25519` / lỗi giải mã | Dùng sai file `recipient.key`. Private key phải khớp với public key đã đăng ký |
