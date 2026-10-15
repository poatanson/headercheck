# headercheck

웹사이트의 **HTTP 보안 헤더**와 **TLS 설정**을 점검하고 항목별 0~100점, 종합 A~F 등급을 매기는 CLI 도구입니다.
외부 스캔 서비스 API 없이 `aiohttp`, `ssl`, `socket`, `cryptography`만으로 동작합니다.

## 설치

Python 3.10 이상이 필요합니다.

```bash
python -m venv .venv
.venv/Scripts/activate        # macOS/Linux: source .venv/bin/activate
pip install -r requirements.txt
```

## 사용법

```bash
# 단일 도메인 (대상이 1개면 항목별 상세 표를 자동으로 출력)
python -m headercheck -d github.com

# 여러 도메인: -d 반복 또는 목록 파일
python -m headercheck -d github.com -d https://example.com/login
python -m headercheck -f domains.txt -v            # -v: 도메인별 상세 표

# 리포트 저장
python -m headercheck -f domains.txt --json out/report.json --md out/report.md

# CI: B 미만(또는 Error)이 하나라도 있으면 exit 1
python -m headercheck -f domains.txt --fail-under B
```

| 옵션 | 기본값 | 설명 |
|---|---|---|
| `-d, --domain` | | 도메인 또는 URL. 여러 번 지정 가능. 스킴이 없으면 `https://`를 붙이고, HTTPS 접속이 안 되면 HTTP로 폴백 |
| `-f, --file` | | 목록 파일. 한 줄에 하나, `#` 뒤는 주석, 중복 제거 |
| `--json PATH` / `--md PATH` | | JSON / Markdown 리포트 저장. 상위 디렉터리는 자동 생성 |
| `-t, --timeout` | 5 | 연결·요청 타임아웃(초). HTTP 요청 1회, TLS 핸드셰이크 1회마다 적용 |
| `-c, --concurrency` | 10 | 동시에 점검할 도메인 수 |
| `--max-redirects` | 3 | 따라갈 최대 리다이렉트 횟수 |
| `--only headers\|tls` | | 한 카테고리만 점검 |
| `-v, --details` | | 도메인별 항목 상세 표 |
| `--fail-under GRADE` | | 이 등급보다 낮거나 `Error`인 대상이 있으면 종료 코드 1 |

종료 코드: `0` 정상, `1` `--fail-under` 기준 미달, `2` 사용법/입력/저장 오류.

### 출력 예시

```
┌─────────────────────────────┬───────┬──────┬─────────┬───────┬─────────────┬───────────────────────┬────────────────────┐
│ 대상                        │ 등급  │ 점수 │ Headers │ TLS   │ 인증서 만료 │ 발급기관              │ 프로토콜           │
├─────────────────────────────┼───────┼──────┼─────────┼───────┼─────────────┼───────────────────────┼────────────────────┤
│ github.com                  │   A   │ 90.5 │ A 90    │ A 91  │        46일 │ Sectigo Limited       │ 1.2, 1.3           │
│ mozilla.org                 │   B   │ 84.8 │ D 69.5  │ A 100 │        59일 │ Google Trust Services │ 1.2, 1.3           │
│ https://expired.badssl.com/ │   F   │   13 │ F 5     │ F 21  │     -4203일 │ COMODO CA Limited     │ 1.0, 1.1, 1.2      │
│ no-such-domain.invalid      │ Error │    - │ Error   │ Error │           - │ -                     │ -                  │
└─────────────────────────────┴───────┴──────┴─────────┴───────┴─────────────┴───────────────────────┴────────────────────┘
```

JSON 리포트는 `targets[]`마다 `grade`, `score`, `categories`, `checks[]`(항목별 점수·상태·원본 값·설명), `grade_caps`, `errors`, 수집 원본(`http`: 리다이렉트 체인과 헤더, `tls`: 인증서·프로토콜·cipher)을 담습니다.

## 구조

```
headercheck/
├── cli.py          # argparse, 진행 표시, 출력/저장, 종료 코드
├── targets.py      # 입력 정규화 (도메인/URL/파일, IDN, 중복 제거)
├── runner.py       # asyncio 오케스트레이션: Semaphore로 동시성 제한, 도메인별 헤더/TLS 병렬
├── headers.py      # aiohttp 수집(수동 리다이렉트) + 헤더 분석 (순수 함수)
├── tls.py          # ssl 기반 인증서/프로토콜 수집 + TLS 분석 (순수 함수)
├── cipherprobe.py  # socket으로 만든 raw ClientHello: 취약 cipher 점검, 프로토콜 폴백
├── scoring.py      # 가중치, 등급, 상한
├── report.py       # rich 콘솔 / JSON / Markdown
└── models.py       # dataclass
```

수집(네트워크)과 판정(순수 함수)을 분리했습니다. HTTP는 aiohttp로 비동기 처리하고, `ssl` 모듈이 blocking이라 TLS 프로브는 `asyncio.to_thread`로 스레드 풀에서 돌립니다.

## 에러 처리

에러가 나도 다른 대상의 점검은 계속 진행합니다. 원인은 리포트의 `errors`와 콘솔 "비고" 칸에 남습니다.

| 상황 | 처리 |
|---|---|
| 존재하지 않는 도메인 (DNS 실패) | 종합 등급 `Error`, 모든 항목 `ERROR` |
| 타임아웃 / 연결 거부 | 해당 카테고리 `Error` → 종합 `Error` |
| TLS 핸드셰이크 완전 실패 | TLS 카테고리 `Error` → 종합 `Error`. 헤더 결과는 그대로 표시 |
| 인증서 검증 실패 (만료, self-signed, 호스트명 불일치) | 검증 없이 다시 접속해 헤더와 인증서를 계속 수집하고, 신뢰 항목 0점 + 등급 상한 F |
| 리다이렉트 3회 초과 / 루프 | Headers 카테고리 `Error` |
| HTTPS → HTTP 다운그레이드 리다이렉트 | 참고 사항으로 기록, HSTS는 최종 HTTP 응답 기준이라 0점 |
| 예상 못 한 내부 예외 | 해당 대상만 `Error`, 예외 내용을 기록 |


## 채점 기준

### 계산 방식

1. 각 점검 항목을 **0~100점**으로 환산합니다.
2. 카테고리 점수 = 항목 점수의 **가중 평균**입니다. 측정하지 못한 항목(`ERROR`)은 빼고 가중치를 다시 정규화합니다. 측정 못 한 것을 0점(없음)으로 처리하지 않기 위해서입니다.
3. 종합 점수 = **Headers 50% + TLS 50%**입니다. `--only headers|tls`로 실행하면 해당 카테고리만 100%로 계산합니다.
4. 점수 → 등급: **A ≥ 90, B ≥ 80, C ≥ 70, D ≥ 60, F < 60**
5. **등급 상한(cap)**: 치명적인 결함 하나가 평균에 묻히지 않도록 아래 상한을 적용합니다. 최종 등급 = min(점수 등급, 상한). 상한 때문에 등급이 내려가면 리포트에 이유를 남깁니다.
6. 대상에 접속할 수 없거나(DNS 실패 등) 한 카테고리를 전혀 측정하지 못하면(TLS 핸드셰이크 실패 등) 종합 등급은 **`Error`**이고, 원인은 `errors`에 기록합니다.

| 상한 | 조건 |
|---|---|
| F | 인증서 만료, 인증서 신뢰 실패(self-signed, 알 수 없는 CA, 호스트명 불일치), NULL/anon/EXPORT/RC4/DES cipher 허용, TLS 1.2·1.3 모두 미지원 |
| C | TLS 1.0 또는 1.1 허용, 3DES cipher 허용 |
| B | HSTS 없음/무효, CSP 없음 |

### 카테고리 가중치

| 카테고리 | 가중치 | 근거 |
|---|---|---|
| Headers | 50% | 브라우저 쪽 공격(XSS, 클릭재킹, 다운그레이드)에 대한 방어 |
| TLS | 50% | 전송 구간의 기밀성과 무결성. 둘 중 하나만 약해도 사이트 전체가 위험하므로 같은 비중을 둠 |

### HTTP 보안 헤더 (카테고리 내 가중치 합 100)

| 항목 | 가중치 | 100점 | 감점 / 낮은 점수 | 가중치 근거 |
|---|---|---|---|---|
| Content-Security-Policy | **30** | script 소스 제한, `object-src 'none'`, `base-uri` 지정 | `'unsafe-inline'`(nonce/hash 없이) −40, script 제한 없음 −40, `*`/`http:`/`https:`/`data:` −30, `'unsafe-eval'` −20, `object-src` 미제한 −10, `base-uri` 없음 −5 · Report-Only만 있으면 30 · 없음 0 | XSS 피해를 줄이는 가장 강력한 수단이자 설정 실수가 가장 많은 헤더 |
| Strict-Transport-Security | **25** | `max-age ≥ 1년` + `includeSubDomains` | 1년 이상이지만 includeSubDomains 없음 90 · 180일 이상 70 · 1일 이상 40 · 1일 미만 20 · `max-age` 없음/0/파싱 불가/HTTP 응답 0 | 없으면 SSL stripping으로 HTTPS 자체를 우회할 수 있음 |
| X-Frame-Options | **15** | `DENY`/`SAMEORIGIN` **또는** CSP `frame-ancestors` | `ALLOW-FROM` 30(최신 브라우저가 무시) · 없음/잘못된 값 0 | 클릭재킹. CSP frame-ancestors로 대체할 수 있어 CSP보다 낮게 둠 |
| X-Content-Type-Options | **10** | `nosniff` | 그 외 값/없음 0 | MIME 스니핑 방지. 값이 하나뿐이고 효과 범위가 좁음 |
| Referrer-Policy | **10** | `no-referrer`, `same-origin`, `strict-origin`, `strict-origin-when-cross-origin` | `origin*` 70 · `no-referrer-when-downgrade` 40 · `unsafe-url` 0 · **없음 50** | 정보 노출 위험. 없을 때 브라우저 기본값(strict-origin-when-cross-origin)이 이미 괜찮아서 50점 |
| Permissions-Policy | **10** | 민감 기능(camera, microphone, geolocation, payment, usb) 4개 이상 제한 | 헤더가 있으면 기본 60 + 제한한 민감 기능마다 +10, `*` 허용마다 −20 · 레거시 Feature-Policy만 있으면 40 · 없음 0 | 심층 방어용. 없다고 바로 공격이 가능해지지는 않음 |

### TLS (카테고리 내 가중치 합 100)

| 항목 | 가중치 | 100점 | 감점 / 낮은 점수 | 가중치 근거 |
|---|---|---|---|---|
| 지원 프로토콜 | **30** | TLS 1.2 + 1.3 (1.0/1.1 비활성) | TLS 1.3 미지원 90 · TLS 1.1 허용 50 · TLS 1.0 허용 30 · 1.2/1.3 모두 미지원 0 | 1.0/1.1은 RFC 8996에서 폐기됨. 다운그레이드 공격 면적 |
| 취약 Cipher | **30** | 취약 cipher를 하나도 받지 않음 | 수락한 그룹 중 가장 낮은 점수 적용: kRSA(PFS 없음) 70 · 3DES(Sweet32) 40 · RC4/DES/EXPORT/NULL/anon 0 | 기밀성이 직접 깨지는 문제 |
| 인증서 신뢰/발급기관 | **25** | 시스템 trust store 기준 체인과 호스트명 검증 통과 | 검증 실패 0 · RSA < 2048bit −50 · SHA-1/MD5 서명 −50 | 신뢰할 수 없는 인증서는 MITM과 구분이 안 됨 |
| 인증서 만료 | **15** | 남은 기간 30일 초과 | 15~30일 70 · 15일 미만 40 · 만료 0 | 장애·경고 위험이지만 시간이 지나면 해결되는 운영 문제. 만료 자체는 상한 F로 따로 처리 |

> 발급기관(issuer)은 점수가 아니라 정보로 표시합니다.

### PASS / WARN / FAIL
항목 점수 90 이상은 `PASS`, 50 이상은 `WARN`, 50 미만은 `FAIL`, 측정 불가는 `ERROR`입니다.

## 측정 방식과 한계

- **헤더**: 대상 URL에 `GET`을 보내고, 리다이렉트는 직접 따라갑니다(기본 최대 3회). 평가는 **최종 응답** 헤더로 합니다. 리다이렉트 횟수를 넘기거나 루프가 생기면 Headers 카테고리를 `Error`로 둡니다. 인증서가 깨진 사이트는 검증 없이 다시 접속해서 헤더를 수집하고, 인증서 문제는 TLS 카테고리에서 채점합니다. 스킴 없이 도메인만 넣었는데 HTTPS 접속이 안 되면 HTTP로 폴백합니다. 이때 HSTS는 무효(0점)입니다.
- **인증서**: `ssl` 모듈로 검증 핸드셰이크를 합니다. 실패하면 `ssl.get_server_certificate`로 검증 없이 인증서를 받아 `cryptography`로 파싱합니다(남은 일수, 발급기관, SAN, 키, 서명 알고리즘).
- **프로토콜**: `ssl.SSLContext`의 `minimum_version = maximum_version`으로 TLS 1.0~1.3을 하나씩 핸드셰이크해 봅니다. TLS ≤ 1.2에서 `ssl`이 실패하면 아래의 raw ClientHello로 한 번 더 확인합니다.
- **취약 cipher**: OpenSSL 3.x 빌드는 대부분 RC4/DES/3DES/EXPORT를 **아예 빼고 배포**되므로 `ssl` 모듈로는 이런 cipher를 제시할 수조차 없습니다. 그래서 `socket`으로 **TLS ClientHello를 직접 만들어** 취약 cipher 그룹만 제시하고, ServerHello에서 서버가 고른 cipher를 확인합니다. 핸드셰이크를 끝까지 하지 않으므로 로컬 OpenSSL과 상관없이 동작합니다. TLS 1.3 cipher는 모두 AEAD라서 점검하지 않습니다.
- 서버가 취약 cipher**만** 허용하면(예: rc4.badssl.com) `ssl` 모듈로는 핸드셰이크가 안 됩니다. 이때 인증서는 raw 핸드셰이크의 Certificate 메시지에서 꺼내고, 체인 검증 항목은 `ERROR`(측정 불가)로 둡니다.
- 한 도메인에 대한 TLS 프로브는 약 12번의 핸드셰이크를 **순차로** 실행합니다. 같은 서버에 동시 접속이 몰리지 않게 하기 위해서입니다. 여러 도메인은 병렬로 처리합니다.
- SNI 기반 다중 인증서, OCSP stapling, 인증서 폐기(CRL/OCSP), TLS 1.3 0-RTT, HTTP/2 등은 점검하지 않습니다.

## 테스트

```bash
pytest
```
단위 테스트는 네트워크를 쓰지 않습니다.
- 헤더와 채점 로직은 순수 함수라서 데이터만 넣어 테스트합니다.
- 인증서는 `cryptography`로 테스트 중에 만듭니다.
- raw ClientHello 파서는 가짜 소켓에 ServerHello 바이트를 넣어 검증합니다.
- DNS 실패와 핸드셰이크 실패는 monkeypatch로 재현합니다.
