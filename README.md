# 👀 Seethru Packet

Seethrough Packet은 mitmproxy 기반으로 http, https, tcp 통신 패킷들을 기록하며, get-flag.py를 실행해 플래그 값을 추출해올 시 플래그가 유출되는 패킷을 별도 파일에 기록합니다. 블랙리스트 문자열들을 설정하여 특정 패킷들을 차단할 수 있으며, Modify 기능 활성화 시 공격 패킷을 바로 차단하지 않고 플래그 유출이 감지되었을 때, 응답 플래그를 원하는 값으로 변경할 수 있습니다.

## 📝 Usage

- [*configure_proxy_docker.py*](#configure_proxy_docker.py)를 통해 프록시 설정을 위한 도커를 만들 수 있습니다.

- 설정한 문제 이름으로 별도 디렉토리가 생성되며, 생성된 [*run_{env_name}_{target_service}_proxy.sh*](#run_{proxy_type}_{env_name}_{target_service}_proxy.sh)을 통해 프록시 도커를 실행할 수 있습니다.

- [*set_iptables_rules.sh*](#set_iptables_rules.sh) 를 통해 최상단 CHAIN을 생성한다.

- 생성한 최상단 CHAIN에 iptables 룰을 추가하여 패킷들이 Seethrough Packet을 거치도록 설정합니다.

  - Example: ```sudo iptables -t nat -A MITM -p tcp \! -s 127.0.0.0/24 --dport 9443 -j REDIRECT --to-ports 19443```

- TLS로 감싼 TCP 서비스는 PROXY_TYPE을 tls로 설정하고 서비스에서 사용하는 서버 인증서(*.crt*)와 개인키(*.key*)를 합쳐 하나의 *.pem* 번들을 만들어 CUSTOM_CERT_PATH로 지정해야 합니다.

- HTTPS 서비스는 PROXY_TYPE을 https로 설정하고 서비스에서 사용하는 서버 인증서(*.crt*)와 개인키(*.key*)를 합쳐 하나의 *.pem* 번들을 만들어 CUSTOM_CERT_PATH로 지정해야 합니다.

- CUSTOM_CERT_PATH는 *seethrue_packet/{env_name}* 경로부터 상대 경로로 지정합니다.


### Usage Example

```bash
#프록시 도커 초기 설정
~/seethru_packet$ python3 configure_proxy_docker.py 
========================================
=== MITM Proxy Configuration Wizard  ===
========================================

--- Available Wargame Environments ---
  [1] atc
  [2] contractor
  [3] https_test
  [4] aisplus
Please choose an option (1-4): 3

--- Exposed Services in 'https_test' ---
  [1] https_post:9443
Please choose an option (1-1): 1

--- Protocol for the selected port ---
  [1] http
  [2] https
  [3] tcp
  [4] tls
Please choose an option (1-4): 2
Use custom certificate? (if unsure, say no) [y/N]: y
Enter path to .pem file (relative to MITM_PROXY dir) [default: /cs/services/https_test/haproxy/backend.pem]: server.pem

----------------------------------------
[SUCCESS] Generated proxy script: https_test/run_https_test_https_post_proxy.sh
----------------------------------------
To use it:
  1. In Seethru_Packet dir and run: ./https_test/run_https_test_https_post_proxy.sh
  2. Check iptables rules: sudo iptables -t nat -L --line-numbers -n -v
  3. If MITM chain doesnt exist: sudo ./set_iptables_rules.sh
  4. Add iptables rules: sudo iptables -t nat -A MITM -p tcp \! -s 127.0.0.0/24 --dport 9443 -j REDIRECT --to-ports 19443

~/seethru_packet$ cd https_test/

#https 복호화를 위한 인증서 파일 생성
~/seethru_packet/https_test$ cat server.crt server.key > server.pem

#프록시 도커 생성
~/seethru_packet/https_test$ ./run_https_test_https_post_proxy.sh 
[INFO] Using custom certificate: server.pem
--- Preparing Proxy ---
  Container: mitmproxy_https_post_9443
  Network:   https_test_default
  Log File:  log_https_https_post_9443

--- Proxying --- 
  Clients connect to  ==> https://<your_vm_ip>:19443
  Proxy forwards to   ==> reverse:https://127.0.0.1:9443

[INFO] Stopping and removing old container if it exists...
[INFO] Starting new proxy container...
24ae00748e0eccb53b5c181b06e86cb590ecdb54863d86c7f52a8e818bce85f2
[SUCCESS] Proxy container 'mitmproxy_https_post_9443' started.
Add iptables rules: sudo iptables -t nat -A MITM -p tcp \! -s 127.0.0.0/24 --dport 9443 -j REDIRECT --to-ports 19443

~/seethru_packet/https_test$ cd ..

#IPTABLES Chain 생성
~/seethru_packet$ sudo ./set_iptables_rules.sh 

#IPTABLES Rule 추가
~/seethru_packet/https_test$ sudo iptables -t nat -A MITM -p tcp \! -s 127.0.0.0/24 --dport 9443 -j REDIRECT --to-ports 19443
```

## 🛠️ Mechanism

### configure_proxy_docker.py

- ```WARGAME_DIR = "/cs/services"```에서 문제 리스트를 읽어옵니다.

- 선택한 문제에서 *docker-compose.yml*을 읽어와 문제에서 사용하는 포트 등 정보들을 불러옵니다.

- 문제 도커 환경 중 seethru_packet을 적용할 서비스, 포트 등을 선택합니다.

- 선택한 정보들을 바탕으로 문제 환경 이름으로 폴더를 생성하고, ```/scripts``` 폴더의 템플릿들과 ```/src``` 폴더의 원본 ```monitor_*.py``` 등 파일로 초기 설정을 완료합니다.

```bash
└── {env_name}
    ├── logs
    │   ├── leak_https_https_post_9443_0027.txt
    │   └── log_https_https_post_9443_0024.txt
    ├── monitor_http.py
    ├── monitor_tcp.py
    ├── run_{proxy_type}_{env_name}_{target_sevice}_proxy.sh
    ├── server.pem # if needed
    ├── tls_wrapper.sh
    └── utils.py
``` 

### set_iptables_rules.sh

- MITM이라는 이름의 IPTABLES 룰 체인을 생성합니다.

- MITM은 최상단 룰로 모든 패킷이 해당 룰을 거치게 됩니다.

- 이 체인에 IPTABLES 룰을 추가해 seethru_packet 도커로 패킷이 리다이렉트 되도록 설정합니다.

### get-flag.py

- *2024 Packet-Capture*에 있던 *get-flag.py*를 사용했습니다.

- 주기적으로 우리 측 플래그를 업데이트하여 파일로 저장합니다.

- 플래그를 가져올 수 있는 파이썬 스크립트를 형식에 맞춰 작성해야됩니다.(ex. *cargotracker.py*)

- 플래그 유출 로그 기록, 플래그 유출 값 Modify 기능은 get-flag가 선행되어야 정상 작동됩니다.

### run_{proxy_type}_{env_name}_{target_service}_proxy.sh

- 프록시 도커를 생성하는 쉘파일입니다.

- 쉘파일 실행 시 마지막에 나오는 IPTABLES룰을 추가해야 정상작동합니다.

- *monitor_\*.py* 등에서 차단 구문 수정 시 이 쉘 파일을 실행하여 도커를 다시 빌드해줘야 적용됩니다.

### monitor_tcp.py

- TCP socat 통신을 담당하는 파이썬 스크립트입니다.

- TCP 통신 발생 시 ```tcp_message(flow: tcp.TCPFlow)``` 함수가 실행되어 추가적인 동작을 수행합니다.

- 모든 패킷 로깅, 플래그 유출 패킷 로깅, 공격 구문 차단, ```ENABLE_MODIFY = True```로 활성화 시 유출되는 플래그 값 변조 등 기능이 존재합니다.

- ```BLOCKED_STRINGS = []```에서 차단 구문을 지정할 수 있습니다.

- ```MODIFIED = "FLAG;rm -rf /"```로 유출되는 플래그 값 변조가 가능합니다.

- TLS를 통한 TCP socat 통신 시, ***server.pem* 파일이 필요합니다**
 
    ```bash
    $ cat server.crt server.key > server.pem
    ```

- TLS로 감싼 TCP 서비스는 PROXY_TYPE을 tls로 설정하면 프록시 컨테이너 내부에서 *tls_wrapper.sh*이  openssl socat을 통해 클라이언트↔프록시, 프록시↔원본 서비스 양방향 TLS를 처리하고, mitmproxy에는 평문 TCP를 전달합니다.

### monitor_http.py

- HTTP 통신을 담당하는 파이썬 스크립트입니다.

- HTTP Response 발생 시 ```response(flow: http.HTTPFlow)``` 함수가 실행되어 추가적인 동작을 수행합니다.

- 모든 패킷 로깅, 플래그 유출 패킷 로깅, 공격 구문 차단, ```ENABLE_MODIFY = True```로 활성화 시 유출되는 플래그 값 변조 등 기능이 존재합니다.

- ```BLOCKED_STRINGS = []```에서 차단 구문을 지정할 수 있습니다.

- ```MODIFIED = "FLAG;rm -rf /"```로 유출될 플래그 값을 어떤 값으로 수정할 지 설정할 수 있습니다.

- HTTPS 통신 시, ***server.pem* 파일이 필요합니다.**

    ```bash
    $ cat server.crt server.key > server.pem
    ```

- mitmdump 옵션 중 --certs 옵션을 통해 자동으로 HTTPS 통신 암복호화를 진행합니다.

### utils.py

- 각종 유틸리티 함수가 존재합니다.

- TLS 암호화가 아닌 별도 인코딩 또는 암호화(serialize, Encrypt with Algorithm) 존재 시 활용할 수 있는 ```encrypt(raw: str)```, ```decrypt(raw: str)```가 있습니다.

- 위 함수는 *monitor_\*.py* 에 기본 적용되어 있으며, 해당 부분에 별도 암복호화를 추가하여 패킷을 평문으로 바꿔 볼 수 있습니다.

### logs

- 로그가 저장되는 디렉토리입니다.

- *leak_{proxy_type}_{env_name}_{target_service}_{target_port}_{time}.txt*: get_flag에서 저장하는 플래그 값을 기준으로 response에 FLAG가 유출됐을 시 기록됨.

- *log_{proxy_type}_{env_name}_{target_service}_{target_port}_{time}.txt*: 모든 로그를 기록함