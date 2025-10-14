# MITM 체인 삭제
# 1) PREROUTING에서 MITM 점프 제거(있으면 여러 번 지워도 됨)
sudo iptables -t nat -D PREROUTING -j MITM 2>/dev/null || true

# 2) MITM 체인 비우기 → 삭제
sudo iptables -t nat -F MITM 2>/dev/null || true
sudo iptables -t nat -X MITM 2>/dev/null || true

# MITM 체인을 PREROUTING 최상단 유지(이미 있으면 생략)
iptables -t nat -N MITM 2>/dev/null || true
iptables -t nat -D PREROUTING -j MITM 2>/dev/null || true
iptables -t nat -I PREROUTING 1 -j MITM
iptables -t nat -F MITM

# (2) 8084 -> 18084 로 로컬 리다이렉트
# iptables -t nat -A MITM -p tcp --dport 8084 -j REDIRECT --to-ports 18084

# (3) 18084 포트 차단
# iptables -I DOCKER-USER 2 -p tcp --dport 18084 -j DROP

# 확인
# sudo iptables -t nat -L PREROUTING -n --line-numbers