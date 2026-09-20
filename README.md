**한국어** | [English](README.en.md)

# trustline

[![npm](https://img.shields.io/npm/v/trustline-scanner?logo=npm)](https://www.npmjs.com/package/trustline-scanner) [![GitHub Marketplace](https://img.shields.io/badge/Marketplace-Trustline-2088FF?logo=github)](https://github.com/marketplace/actions/trustline-off-chain-scan) [![Demo](https://img.shields.io/badge/데모_영상-YouTube-FF0000?logo=youtube)](https://youtu.be/ACdar3TTPXI)

▶ 데모 영상: https://youtu.be/ACdar3TTPXI

오프체인 인프라 보안 스캐너. 한 번의 침해를 Web3 프로젝트 오프체인 스택(프론트엔드,
클라우드, DNS, 시크릿) 전체 장악으로 번지게 만드는 설정 실수를 찾아냅니다.

실제 사고에서 출발했습니다. Next.js 앱이 인증 없는 RCE(React2Shell)에 뚫렸고, 피해가
번질 수 있었던 건 설정 실수가 연쇄로 이어졌기 때문입니다. trustline은 바로 그 실수들을
출시 전에 점검합니다.

## 빠른 시작

설치 없이, 자기 저장소에서 바로 실행합니다 (Node 18+):

```bash
npx trustline-scanner scan .                       # 현재 폴더의 오프체인 설정을 점검
npx trustline-scanner scan . --html > report.html  # 공유용 HTML 리포트
npx trustline-scanner scan . --sarif > out.sarif   # GitHub 코드 스캐닝용 SARIF
```

npm 배포 전이거나 최신 소스를 쓰고 싶으면 GitHub에서 직접 실행할 수도 있습니다:

```bash
npx github:kyle-park-io/trustline scan .
```

AI 에이전트에게 그대로 시켜도 됩니다: "배포 전에 `npx trustline-scanner scan .`를
돌려서 critical/high가 나오면 고쳐줘." 종료 코드가 0이 아니면 잡을 게 있다는 뜻입니다.
`scan`은 완전히 오프라인이라 코드를 밖으로 보내지 않습니다.

## 왜

dApp 보안의 관심은 스마트 컨트랙트로 쏠리지만, 실제 사고는 오프체인 스택에서 터지는
경우가 많습니다. 여기의 검사 하나하나는 그 사고에서 나온 실제 발견(과 그 조치)에
대응됩니다.

## 위협 모델

오픈 시큐리티 트랙이 요구하는 네 가지 선언을 먼저 밝힙니다.

- **위협 모델(Threat model).** 오프체인 서버에서 코드 실행을 얻는 원격 공격자
  (이번 사고의 진입점은 React2Shell, `CVE-2025-55182`이며, 북한 연계 행위자도
  범위에 포함). 오프체인 운영·권한 계층은 장악할 수 있지만, 온체인 컨트랙트 로직
  자체를 깨는 것은 범위 밖이고 컨트랙트 감사와 온체인 가드레일의 몫입니다.
- **보호 대상(Protected asset).** dApp의 키·시크릿·자금·사용자 데이터, 그리고 그것을
  쥐고 있는 오프체인 운영 계층.
- **실패 조건(Failure condition).** 한 번의 침해가 반경을 넘어 키·자금, 또는 클라우드
  계정 전체로 번지는 것.
- **검증 방법(Validation method).** `scan examples/vulnerable` = critical 18 / 총 34건
  (종료코드 1) 대 `scan examples/safe` = 0건(종료코드 0), 실제 서버의 조치 전후 실측,
  자체 테스트 35/35, 그리고 `investigate-c2`로 온체인을 읽기 전용으로 라이브 복원.
  수치는 아래 참조.

## 모듈 (v0.1)

모듈은 세 축으로 돕니다. **반경 최소화**(한 번의 침해가 번지지 않게), **탐지**(침해와
그것을 가리는 사각을 잡기), **대조**(이 인프라가 이미 알려진 공격자 영역에 닿아 있는가).


- `vulnerable-dependency`: 선언된 버전이 알려진 취약 릴리스와 일치하는 의존성을,
  소규모 큐레이션 어드바이저리 셋([`data/advisories.json`](data/advisories.json))과
  대조합니다. 범용 npm-audit가 아닙니다. 이 셋은 이번 사고의 진입점(React2Shell,
  `CVE-2025-55182`, `react-server-dom-*` 패키지)과 잘 알려진 Web3 공급망 사고
  (`@ledgerhq/connect-kit`)에 앵커돼 있습니다. 이번 침해를 가능하게 한 바로 그 취약
  구성요소를 출시 전에 잡는 것이 목적입니다. `package.json`에 선언된 버전을 기준으로
  매칭하며, 락파일 기반 범위 해석은 향후 과제입니다.
- `bundle-secrets`: 소스나 브라우저에서 접근 가능한 빌드 산출물에 들어간 시크릿(개인키,
  하드코딩된 API 키·토큰, JWT). 클라이언트 번들의 시크릿은 방문자 누구나 읽을 수 있습니다.
- `network-exposure`: 관리·데이터베이스 포트(SSH, RDP, Postgres, Redis 등)를
  `0.0.0.0/0`으로 여는 클라우드 방화벽 규칙, 그리고 CDN 뒤가 아니라 인터넷에 직접
  노출된 오리진. 내보낸 방화벽 JSON을 읽습니다
  (`gcloud compute firewall-rules list --format=json > firewall.json`).
- `iam-privilege`: 클라우드 IAM 과다 권한. `roles/owner`·`roles/editor`에 묶인
  서비스계정, `allUsers`에 부여된 IAM 역할, 만료 없는 사용자 관리형 서비스계정 키.
  내보낸 IAM JSON을 읽습니다
  (`gcloud projects get-iam-policy PROJECT --format=json > iam-policy.json`,
  `gcloud iam service-accounts keys list --iam-account=SA --format=json > sa-keys.json`).
- `account-wide-credentials`: 리소스 범위로 충분한데도 계정·프로젝트 전체를 여는 단일
  자격증명. Cloudflare 글로벌 API 키(`X-Auth-Key` / `CLOUDFLARE_API_KEY`), GCP
  `cloud-platform` OAuth 스코프, `*`에 `*`를 허용하는 AWS 정책, classic GitHub PAT.
  이 중 하나만 유출돼도 계정 전체가 넘어갑니다.

- `persistence-artifacts`: 호스트의 백도어 영속화 지표. 숨긴 바이너리를 띄우는 crontab
  `@reboot`, 숨김·임시 실행파일을 돌리는 systemd 유닛, 숨긴 XDG autostart 항목, 숨긴
  프로세스를 백그라운드로 띄우는 셸 rc 파일. 홈 디렉터리나 내보낸 사본을 대상으로 지정합니다.
- `attack-signals`: 로그에 남은 공격 시도(탐지 사각). 리버스 셸, `curl|bash` 페이로드
  다운로드, 앱에서 실패한 셸 명령, SSRF-메타데이터 프로브, 크립토마이너 참조. 모니터가
  경보해야 할 것들입니다. 공격은 대개 피해 단계 전에 신호를 남기고, 그게 탐지·대응의
  창입니다.
- `audit-telemetry-gap`: 사각이 되기 전에 꺼져 있는 텔레메트리. GCP Data Access 감사
  로그 미활성(또는 `exemptedMembers`), VPC 플로우 로그 비활성, 애플리케이션 로깅·모니터링
  침묵. 이번 사고의 바로 그 사각이었습니다. Data Access 로그가 꺼져 있어 RCE 이후 횡적
  이동을 확인도 배제도 할 수 없었습니다.
- `known-ioc`: 이번 사고의 온체인 포렌식에서 뽑은 알려진 악성 지표와 파일을 대조합니다.
  EtherRAT C2 컨트랙트와 엔드포인트(도메인, IP), 주소 포이즈닝 드레이너 지갑, WEMIX
  세탁 경로, `setString` C2 기록 셀렉터, 호모글리프 위조 토큰 문자열. 설정이 위험한지
  판단하는 다른 모듈과 달리, 이 모듈은 인프라가 이미 공격자가 통제하는 영역에 닿아 있는지
  묻습니다. 한 건만 맞아도 냄새가 아니라 침해 가능성입니다. 데이터셋
  ([`data/iocs.json`](data/iocs.json))은 공격자 통제 지표만 담습니다. 악용됐던 정상
  서비스(거래소 핫월렛, 스왑 라우터, 브리지)는 스캔해도 아무것도 뜨지 않도록 일부러
  제외했습니다.

향후 계획: 락파일 기반 버전 매칭을 갖춘 더 넓은 어드바이저리 셋, 컨테이너 이미지에 구운
시크릿, 배포 후 지속 모니터링.

## 사용법

```bash
pnpm install       # dev-only deps (typescript); zero runtime dependencies
pnpm build
node dist/src/cli.js scan <dir>          # human-readable
node dist/src/cli.js scan <dir> --json   # machine-readable
node dist/src/cli.js scan <dir> --html  > report.html   # standalone HTML report
node dist/src/cli.js scan <dir> --sarif > trustline.sarif  # SARIF 2.1.0
```

critical 또는 high가 하나라도 있으면 종료코드가 0이 아니라서, 그대로 CI에 붙습니다.

## CI 연동

`scan --sarif`는 SARIF 2.1.0을 내보내, 발견 항목이 GitHub Security 탭과 PR 주석에
뜹니다. composite GitHub Action([`action.yml`](action.yml))이 스캔을 감싸며,
`upload-sarif`로 연결합니다.

```yaml
# .github/workflows/trustline.yml
name: trustline
on: [push, pull_request]
jobs:
  scan:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write   # required to upload SARIF
    steps:
      - uses: actions/checkout@v4
      - uses: kyle-park-io/trustline@v0.1.0
        with:
          path: .
          fail-on-findings: "true"
      - uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: trustline.sarif
```

이 저장소 자체의 CI([`.github/workflows/ci.yml`](.github/workflows/ci.yml))는 모든
push·PR에서 `pnpm build && pnpm test`를 돌립니다.

## 위협 인텔: 블록체인 C2 (네트워크 필요)

이번 사고에서 관측된 EtherRAT는 명령·제어(C2) 주소를 이더리움 스마트 컨트랙트에서
읽어 옵니다. 그래서 도메인을 차단해도 죽지 않습니다. `investigate-c2`는 그 컨트랙트의
공개 온체인 데이터를 읽어, 운영자가 써 넣은 C2 값을 복원합니다. 읽기 전용입니다.
트랜잭션을 보내지 않고 컨트랙트와 상호작용하지 않습니다. `eth_call`은 로컬 시뮬레이션입니다.

```bash
node dist/src/cli.js investigate-c2                 # defaults to the EtherRAT C2 contract
node dist/src/cli.js investigate-c2 <address> --json
```

### 함대 모드: `--cluster`

`--cluster`는 C2 컨트랙트 하나에서 그 주변 함대를 되짚습니다. 배포자(컨트랙트 생성자),
배포자에게 가스를 댄 자금 허브, 그리고 허브 운영자가 (`setString` 셀렉터로) C2 문자열을
써 넣은 형제 C2 컨트랙트까지. 경계 안에서 도는 best-effort, 읽기 전용입니다.

```bash
node dist/src/cli.js investigate-c2 --cluster       # fleet around the default seed
node dist/src/cli.js investigate-c2 <address> --cluster --json
```

### 주소 포이즈닝: `investigate-poison`

한 주소의 공개 이력에서 주소 포이즈닝을 점검합니다. 유사 주소(복붙을 속이려고 앞 4자·뒤
4자를 맞춘 상대), 값 모방 더스트(이력에 심은 아주 작은/0 전송), 위조·호모글리프
토큰(ETH/USDC를 흉내 낸 가짜 토큰). 읽기 전용입니다.

```bash
node dist/src/cli.js investigate-poison <address>
node dist/src/cli.js investigate-poison <address> --json
```

`investigate-*` 명령만 네트워크를 씁니다(키 없는 공개 RPC + 익스플로러). `scan`은 완전히
오프라인입니다. 이 명령들이 무엇을 복원하는지(EtherRAT 다중 C2 캠페인과 주소 포이즈닝
드레이너 작전), IOC와 재현 방법은 [`ONCHAIN-FORENSICS.md`](ONCHAIN-FORENSICS.md)를
보세요.

## 데모

```bash
pnpm build
node dist/src/cli.js scan examples/vulnerable   # findings, exit 1
node dist/src/cli.js scan examples/safe          # clean, exit 0
```

`examples/vulnerable`는 "조치 전"(실수가 있는 상태), `examples/safe`는 "조치
후"(같은 스택을 고친 상태)입니다. 여기의 어떤 것도 실제 서비스를 건드리지 않고 로컬
파일만 읽습니다.

## 테스트

```bash
pnpm test
```

두 예제에 대해 스캐너를 돌려 조치 전후 동작을 검증합니다.

## TRUST404 제출

이 저장소는 TRUST404(트랙 05, 오픈 시큐리티) 제출용 공개·비식별 산출물입니다. 여기 있는
모든 것은 실제 오프체인 사고에서 이번 제출을 위해 만든 v0.1입니다. 세 축(반경 최소화,
탐지, IOC 대조)에 걸친 `scan` 모듈(이번 사고의 진입점에 앵커된 `vulnerable-dependency`
포함), 함대(`--cluster`) 모드를 갖춘 온체인 명령 `investigate-c2`, 주소 포이즈닝 점검
`investigate-poison`, CI용 GitHub Action과 함께 제공되는 HTML·SARIF 리포트, 합성
`examples/`, 그리고 자체 테스트. 가장 독창적인 부분은 온체인 명령입니다. 공개·읽기 전용
데이터만으로 악성코드 계열의 명령·제어 값(과 그 주변 함대)을 이더리움 스마트 컨트랙트에서
복원하고, 그 조사를 `known-ioc` 데이터셋으로 바꿉니다.

2026-09-20 검증: `scan examples/vulnerable` = critical 18 / 총 34건(종료코드 1),
`scan examples/safe` = 0건(종료코드 0), 자체 테스트 35/35 통과. `investigate-c2
--cluster`와 `investigate-poison`은 공개 체인 데이터에 대해 라이브로 확인했습니다.

## AI 사용

방향과 판단은 저자가 잡았고, AI(Anthropic의 Claude)는 도구로 활용했습니다. 스캐너·테스트
작성과 리팩터링, 사고 분석, 검사의 근거가 된 읽기 전용 온체인 포렌식처럼 반복이 많고
조사량이 큰 부분에서 특히 도움이 됐습니다. 모든 발견·수치·온체인 주장은 포함하기 전에
1차 출처나 라이브 데이터로 검증했고, 저자가 최종 검토했습니다.

## 참고

- `scan`은 완전히 오프라인으로 돌며 로컬 파일(소스, 빌드 산출물, 내보낸 클라우드 설정)만
  읽습니다. 살아 있는 서비스를 공격하지 않습니다.
- `investigate-*` 명령만 네트워크를 쓰고, 공개 블록체인 데이터만 읽습니다(트랜잭션 없음,
  상호작용 없음).
- `examples/` 아래는 전부 합성입니다. 실제 시크릿이나 호스트명은 없습니다.
