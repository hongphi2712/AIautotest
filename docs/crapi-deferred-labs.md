# DEFERRED Labs — Nguy Hiểm, Note Làm Sau (An Toàn Máy)

> **Ngày:** 2026-08-31  |  **Epic:** CRAPI-SEC  |  **Story:** CRAPI-7  
> **Nguyên tắc:** Lab có side-effect hệ thống (DoS, xóa, ghi DB, egress) → không chạy auto trong CRAPI-5. Chỉ chạy manual sau khi review `requires_confirmation` + backup.

| # | Challenge | OWASP | flare AnToanAI | Endpoint | Payload ví dụ | `requires_confirmation` | Rủi ro máy | Cách chạy an toàn | Jira |
|---|---|---|---|---|---|---|---|---|---|
| **6** | L7 DoS via contact-mechanic | API4 Lack Rate Limit | `rate_limit` | `POST http://127.0.0.1:8888/workshop/api/mechanic/contact` (thực tế `POST /workshop/api/shop/contact` tùy ingress) | 100× `Promise.all` parallel | `true` | CPU `crapi-workshop` limit 1.0/512M, DB pool 500, có thể treo `postgres/mongodb` | Chạy với `max_requests=10` + `per_host=2/s`, ngoài giờ, `docker stats` monitor, `docker compose restart crapi-workshop` sau | CRAPI-7.1 |
| **7** | BFLA Delete video người khác | API5 BFLA | `auth_bypass` | `DELETE http://127.0.0.1:8888/community/api/v2/videos/{id_other}` (hoặc `/community/api/videos/{id}`) | `DELETE` với token user thường | `true` (path contains `delete`) | Xóa data người khác, không khôi phục | Chỉ tạo video test của chính mình rồi xóa video đó; không đụng video seed | CRAPI-7.2 |
| **9** | Increase balance $1000+ (biến thể 8) | API6 Mass Assignment | `auth_bypass` | `PUT http://127.0.0.1:8888/workshop/api/shop/orders/{ownId}` | `{price:9999, quantity:10}` hoặc `{balance:10000}` | `true` | Sửa balance DB, ảnh hưởng tài chính mock | Chạy trên order/ user test riêng, sau đó `DELETE` hoặc reset DB `docker volume rm` | CRAPI-7.3 |
| **10** | Update internal video properties | API6 | `secret_leak` / `auth_bypass` | `PUT http://127.0.0.1:8888/community/api/videos/{id} {internal_price:0, converted:false}` | field leak từ Ch5 | `true` (contains `update`) | Ghi DB, có thể break Ch5 | Chỉ update video do test tạo | CRAPI-7.4 |
| **11** | SSRF `www.google.com` | API7 SSRF | `open_redirect` / custom | `POST /workshop/api/shop/orders {callbackUrl:"https://www.google.com"}` hoặc `POST /identity/api/auth/... {url:"https://www.google.com"}` | `https://www.google.com` | `false` nhưng scope chặn `evil.com` → cần payload nội bộ | Egress ra internet, có thể bị firewall log | Thay bằng `http://host.docker.internal:8888/health` hoặc `http://crapi-identity:8080/health` nội bộ trước; chỉ khi pass mới thử `google.com` qua `api.mypremiumdealership.com` gateway | CRAPI-7.5 |
| **13** | SQLi redeem claimed coupon (modify DB) | API8 Injection | `sqli` | `POST http://127.0.0.1:8888/workshop/api/shop/coupon/redeem {coupon_code:"' OR 1=1--"}` hoặc `'; UPDATE orders SET status='returned'` | `"' OR '1'='1"` | `true` nếu `POST` | `UPDATE/DELETE` DB, corrupt | Chỉ dùng read-only payload `"' OR 1=1--"` trước, không `; UPDATE`; backup `pg_dump` trước | CRAPI-7.6 |

## Checklist Trước Khi Chạy Bất Kỳ DEFERRED Lab

- [ ] Đã backup `docker compose exec postgresdb pg_dump -U admin crapi > backup.sql`
- [ ] Đã tạo user/order/video test riêng (không dùng seed `admin@example.com`)
- [ ] `config.json:security.max_requests` giảm xuống 10, `per_host_requests_per_sec=2`
- [ ] `requires_confirmation:true` → chờ WS `security_confirm` banner, manual Approve
- [ ] Monitor `docker stats --no-stream` — nếu CPU >80% 30s → `Ctrl+C` + `docker compose restart`
- [ ] Sau chạy: `docker compose exec postgresdb psql -U admin -c "SELECT count(*) FROM orders"` verify

## Mapping Sang Playwright `test.skip`

Trong `tests/e2e/crapi.direct.spec.ts`:

```ts
test.skip('CRAPI-7.1 ch6 DoS contact-mechanic [DEFERRED]', async () => { /* ... */ });
test.skip('CRAPI-7.5 ch11 SSRF google.com [DEFERRED]', async () => { /* ... */ });
```

Bật khi sẵn sàng: `npx playwright test --grep "DEFERRED" --workers=1`.

---
*File này là deliverable của CRAPI-7. Không chạy auto trong CRAPI-5.*
