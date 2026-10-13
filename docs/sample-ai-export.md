# API test log — Shop_API_pentest (exported 2026-10-13 04:43)

How to read this log (exported by the API Logging Burp extension):
- Each API has one or more **original requests** (the baseline, shown with full request and response),
  then every **test** sent from Repeater, an AI agent, or Intruder, in order.
- A test lists what differs from its original: `~` modified (`old → new`), `-` removed, `+` added,
  `§` Intruder payload position. Locations: method, path, query, header, cookie, body (`$.a.b` = JSON field).
- `→ 403 · 82 B · 699 ms` is the response status, size and time of that test.
- `<#a1b2c3d4>` is a masked value (field listed under Masked fields), `<userA>` a labeled token.
- "What was tested" summarizes the tests; "Never modified" lists fields of the original no test touched yet.

## Overview

- 3 APIs with a log: 3 tested, 0 sent but not tested; 9 tests in total
- 4 APIs in scope seen in Proxy history but never tested (listed at the end)

## POST /api/v2/auth/login

- Host: `https://shop-api.example.com:443`
- Status: tested
- Tests: 5 tests (Repeater 3, AI 1, Intruder 1 attack)
- Responses seen: 200×1, 401×2, 500×1

### What was tested

- body `$.password`: modified 1×, Intruder payload position — values tried: <#2224a84f>
- body `$.username`: modified 2× — values tried: "alice'--", "' OR '1'='1"
- header `X-Device-Id`: removed 1×
- Intruder: 1 attack, 10 requests

Never modified (fields of original #1): header `Host`, header `User-Agent`, header `Content-Type`, body `$.remember`

### Original request #1 (Send to Repeater, tracked, 2026-10-13 04:42:40)

Request:
```http
POST /api/v2/auth/login HTTP/1.1
Host: shop-api.example.com
User-Agent: ShopApp/5.2 (iOS 18.1)
X-Device-Id: 7f3c9a12e4b8
Content-Type: application/json

{"username":"alice","password":"<#6676a003>","remember":true}
```

Response:
```http
HTTP/1.1 200 OK
Content-Type: application/json
Set-Cookie: sid=9d1f4c0e2b7a; Path=/; HttpOnly

{"token":"eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhbGljZSIsInJvbGUiOiJ1c2VyIn0.cDTq8vL0dCwVnF2kH","user":{"id":1042,"name":"alice","role":"user"}}
```

### Tests (oldest first)

```
#2  04:42:41  [Repeater]  POST /api/v2/auth/login HTTP/1.1   → 401 · 61 B · 165 ms
    ~ body    $.password   <#6676a003> → <#2224a84f>
#3  04:42:41  [Repeater]  POST /api/v2/auth/login HTTP/1.1   → 500 · 1,204 B · 150 ms
    ~ body    $.username   "alice" → "alice'--"
#4  04:42:41  [Repeater]  POST /api/v2/auth/login HTTP/1.1   → 401 · 61 B · 150 ms
    ~ body    $.username   "alice" → "' OR '1'='1"
#5  04:42:42  [AI:claude]  POST /api/v2/auth/login HTTP/1.1   → 200 · 412 B · 152 ms
    - header  X-Device-Id
#6  04:42:42  [Intruder]  POST /api/v2/auth/login HTTP/1.1
    § body    $.password
    → 10 requests · 401×9  200×1 · 61–412 B · < 1 s
```

---

## GET /api/v2/orders/{id}

- Host: `https://shop-api.example.com:443`
- Status: tested
- Tests: 3 tests (Repeater 2, AI 1)
- Responses seen: 200×1, 401×1, 403×1

### What was tested

- path `[3]`: modified 2× — values tried: 10453, 1
- header `Authorization`: removed 1×

Never modified (fields of original #1): header `Host`, header `Accept`

### Original request #1 (Proxy history, 2026-10-13 04:42:42)

Request:
```http
GET /api/v2/orders/10452 HTTP/1.1
Host: shop-api.example.com
Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhbGljZSIsInJvbGUiOiJ1c2VyIn0.cDTq8vL0dCwVnF2kH
Accept: application/json

```

Response:
```http
HTTP/1.1 200 OK
Content-Type: application/json

{"id":10452,"userId":1042,"items":2,"total":59.90,"status":"shipped"}
```

### Tests (oldest first)

```
#2  04:42:42  [Repeater]  GET /api/v2/orders/10453 HTTP/1.1   → 200 · 233 B · 150 ms
    ~ path    [3]   10452 → 10453
#3  04:42:43  [Repeater]  GET /api/v2/orders/10452 HTTP/1.1   → 401 · 38 B · 150 ms
    - header  Authorization
#4  04:42:43  [AI:claude]  GET /api/v2/orders/1 HTTP/1.1   → 403 · 41 B · 150 ms
    ~ path    [3]   10452 → 1
```

---

## PUT /api/v2/users/{id}/profile

- Host: `https://shop-api.example.com:443`
- Status: tested
- Tests: 1 test (Repeater 1)
- Responses seen: 200×1

### What was tested

- body `$.role`: added 1× — values tried: "admin"

Never modified (fields of original #1): header `Host`, header `Authorization`, header `Content-Type`, body `$.displayName`, body `$.phone`

### Original request #1 (Proxy history, 2026-10-13 04:42:44)

Request:
```http
PUT /api/v2/users/1042/profile HTTP/1.1
Host: shop-api.example.com
Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhbGljZSIsInJvbGUiOiJ1c2VyIn0.cDTq8vL0dCwVnF2kH
Content-Type: application/json

{"displayName":"Alice","phone":"+84901234567"}
```

Response:
```http
HTTP/1.1 200 OK
Content-Type: application/json

{"id":1042,"displayName":"Alice","role":"user"}
```

### Tests (oldest first)

```
#2  04:42:43  [Repeater]  PUT /api/v2/users/1042/profile HTTP/1.1   → 200 · 74 B · 150 ms
    + body    $.role = "admin"
```

---

## Untested APIs in scope (from Proxy history)

- GET https://shop-api.example.com:443/api/v2/admin/users (1 request)
- GET https://shop-api.example.com:443/api/v2/cart (1 request)
- POST https://shop-api.example.com:443/api/v2/payments/checkout (1 request)
- GET https://shop-api.example.com:443/api/v2/products (1 request)
