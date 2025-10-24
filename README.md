# 👀 Seethru Packet

mitmproxy 기반으로 HTTP/HTTPS/TCP/SSH 트래픽을 프록시하고 패킷/FLAG 유출 로그를 기록합니다. ```ENABLE_MODIFY=True```로 설정 시, FLAG 값을 원하는 ```MODIFIED``` 값으로 변경하여 response 합니다.

- 프록시 스크립트 생성: `python3 configure_proxy_docker.py`
- iptables 체인 준비: `sudo ./set_iptables_rules.sh`
- 프록시 실행: `./{env}/run_{env}_{service}_proxy.sh`
- 리다이렉트 룰 추가 예시: `sudo iptables -t nat -A MITM -p tcp ! -s 127.0.0.0/24 --dport <원본포트> -j REDIRECT --to-ports <프록시포트>`

## Simple Usage

1) iptables 체인 준비(최상단 MITM 체인 생성)

```bash
$ sudo ./set_iptables_rules.sh

$ sudo iptables -t nat -L --line-numbers -n -v   # 확인
```

2) 프록시 스크립트 생성 및 실행

```bash
$ python3 configure_proxy_docker.py

$ ./{env}/run_{env}_{service}_proxy.sh

# 실행 출력 마지막 줄을 참고해 리다이렉트 룰 추가
$ sudo iptables -t nat -A MITM -p tcp ! -s 127.0.0.0/24 --dport <원본포트> -j REDIRECT --to-ports <프록시포트>
```

3) 로그 뷰어(선택)

```bash
$ python3 {env}/logs/web.py -p 14284 --password <원하면>
```

4) get-flag(선택)

```bash
$ python3 get-flag.py --name cargotracker start
$ python3 get-flag.py --name cargotracker status
$ python3 get-flag.py --name cargotracker stop
```

* 프록시 컨테이너는 `{repo_root}/flags/{env}`를 `/flags`로 마운트합니다.
* get-flag.py를 실행하기 위해선 문제에 따라 flag를 추출해오는 스크립트를 get_flag 경로에 저장해야합니다.

## 구성 요소

- configure_proxy_docker.py
  - `WARGAME_DIR = "/cs/services"`에서 환경 목록을 읽고 `docker-compose.yml`을 파싱해 실행 환경을 탐지합니다.
  - 선택한 정보로 `{env}` 디렉토리를 만들고, 모니터 스크립트와 템플릿, TLS 래퍼, 로그 뷰어 등을 복사합니다.
  - 실행 스크립트 `run_{env}_{service}_proxy.sh`를 생성합니다.

- scripts/run_proxy_template.sh, scripts/run_proxy_template_ssh.sh
  - Docker 이미지 `mitmproxy/mitmproxy`(HTTP/HTTPS/TCP/TLS) 또는 ssh-mitm(SSH)를 사용합니다.
  - 생성된 `run_*` 스크립트는 직접 수정하지 말고 템플릿을 수정한 뒤 재생성하세요.

- src/monitor_http.py, src/monitor_tcp.py
  - mitmdump 기반의 플러그인으로 개발됨
  - 공통: `{env}/logs/log_*_{HHMM}.txt`에 모든 트래픽을 저장, `/flags` 하위 최근 플래그와 매칭되면 `{env}/logs/leak_*_{HHMM}.txt`로 별도 저장.
  - 차단: `BLOCKED_STRINGS`에 포함된 문자열이 요청(HTTP) 또는 클라이언트 메시지(TCP)에 있으면 차단하거나, Modify 모드에서는 유출 응답만 치환.
  - HTTP는 WebSocket 메시지도 로깅/누출 탐지/치환 로직 포함.

- src/utils.py
  - `FlagCache`가 `/flags`에서 최신 라운드 플래그를 비동기 갱신.
  - `encrypt`/`decrypt` 훅으로 서비스 고유 인코딩/암호화 해제를 주입 가능.

- get-flag.py, get_flag/*
  - `settings.yml` 스케줄을 기준으로 `{repo_root}/flags/{service}`에 플래그 파일 기록.
  - 예시: `get_flag/cargotracker.py`

- set_iptables_rules.sh
  - NAT PREROUTING에 `MITM` 체인을 최상단으로 생성/유지. 개별 포트 리다이렉트는 MITM 체인에 추가.

- bin/
  - 로컬 mitmproxy 바이너리가 포함되어 있으나, 생성 스크립트는 기본적으로 Docker 이미지 `mitmproxy/mitmproxy`를 사용합니다.

## 프로토콜별 안내

- HTTP/HTTPS
  - HTTPS는 서버 인증서(.crt)+개인키(.key)를 결합한 PEM 번들을 `CUSTOM_CERT_PATH`로 지정.
  - 예: `cat server.crt server.key > server.pem`

- TCP
  - 평문 TCP는 `mitmdump --mode reverse:tcp://`로 프록시.

- TLS(임의 TCP+TLS)
  - 컨테이너 내 `tls_wrapper.sh`가 양단 TLS를 처리, mitmproxy에는 평문 TCP 전달. PEM 번들 필수.

- SSH
  - `{env}` 디렉토리에 포함된 ssh-mitm 이미지를 빌드해 실행.
  - 필요 입력: 호스트키 알고리즘, 서버/클라이언트 개인키 경로, 로그인 사용자명.
  - FLAG 유출 탐지 기능 외, 다른 기능은 불안정한 경우가 많아 수정 필요.
  - `ssh-mitm/sshmitm/plugins/ssh/seethru.py`를 플러그인으로 사용하여 원하는 기능을 수행하도록 수정 가능.

## 로그와 파일

- 일반 로그: `{env}/logs/log_<proto>_<service>_<port>_{HHMM}.txt`
- 유출 로그: `{env}/logs/leak_<proto>_<service>_<port>_{HHMM}.txt`
- 로그 뷰어: `python3 {env}/logs/web.py -p 14284`
  - 웹으로 로그를 공유해 쉽게 확인할 수 있도록 함.