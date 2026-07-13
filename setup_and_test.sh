#!/usr/bin/env bash

# Rocky Linux Packet Generator Setup & Test Script
# 이 스크립트는 Rocky Linux 환경에서 root 권한으로 실행해야 합니다.

set -e

# 1. Root 권한 체크
if [ "$EUID" -ne 0 ]; then
  echo "오류: 이 스크립트는 반드시 root 권한(sudo)으로 실행해야 합니다."
  exit 1
fi

echo "=== 1. 필수 패키지 설치 중 (gcc, make, tcpdump) ==="
dnf install -y gcc make tcpdump

echo "=== 2. 소스 코드 빌드 중 ==="
make clean
make

echo "=== 3. 네트워크 인터페이스 자동 감지 ==="
# 기본 라우팅을 사용하는 네트워크 인터페이스 감지
IFACE=$(ip route show | grep default | awk '{print $5}' | head -n 1)

# 감지되지 않을 경우 fallback 처리
if [ -z "$IFACE" ]; then
  # lo(루프백)을 제외한 첫 번째 활성화된 인터페이스 찾기
  IFACE=$(ip -o link show | awk -F': ' '$2 != "lo" && $3 ~ /UP/ {print $2}' | head -n 1)
fi

if [ -z "$IFACE" ]; then
  echo "경고: 활성화된 물리 네트워크 인터페이스를 찾지 못했습니다. 루프백(lo) 인터페이스로 진행합니다."
  IFACE="lo"
fi

echo "감지된 네트워크 인터페이스: $IFACE"

echo "=== 4. 패킷 테스트 송출 및 tcpdump 검증 시작 (5초간 실행) ==="
# tcpdump를 백그라운드에서 실행하여 pktgen이 보내는 패킷 캡처 (HTTP 및 MySQL 통신 필터링)
# pktgen의 payload 텍스트가 보이도록 -A 옵션 사용
echo "tcpdump 백그라운드 대기 중..."
tcpdump -i "$IFACE" -nn -A "tcp port 80 or tcp port 8080 or tcp port 3306" -c 15 > tcpdump_test.log 2>&1 &
TCPDUMP_PID=$!

# 조금 대기 후 패킷 생성기 백그라운드 시작
# 시뮬레이션: Users 100, Webs 5, WAS 2, DB 1, 초당 1000 패킷 전송, 1분 실행 제한 설정
sleep 1
echo "pktgen 실행 중..."
./pktgen -i "$IFACE" --users 100 --webs 5 --was 2 --dbs 1 -r 1000 -t 1 > /dev/null 2>&1 &
PKTGEN_PID=$!

# 5초간 패킷 주입 진행
echo "데이터 전송 및 캡처 중... (5초 대기)"
sleep 5

# 강제 종료하여 통계 로그 저장 유도 (SIGINT 전송)
echo "테스트 종료 및 리소스 정리 중..."
kill -SIGINT $PKTGEN_PID || true
kill $TCPDUMP_PID || true
sleep 1

echo "=== 5. tcpdump로 캡처된 패킷 내용 검증 (일부 출력) ==="
if [ -f tcpdump_test.log ] && [ -s tcpdump_test.log ]; then
  echo "--------------------------------------------------"
  head -n 40 tcpdump_test.log
  echo "--------------------------------------------------"
  echo "이외 상세 내역은 'tcpdump_test.log' 파일에서 확인하실 수 있습니다."
else
  echo "패킷 캡처 실패 또는 캡처된 패킷이 없습니다. (Raw Socket 주입이 허용되는 인터페이스인지 확인해 주세요)"
fi

echo "=== 6. 생성된 실행 통계 및 IP 매핑 로그 출력 (YYYYMMDD-HHMMSS 디렉토리) ==="
# 가장 최근에 생성된 YYYYMMDD-HHMMSS 형태의 디렉토리 찾기
LATEST_DIR=$(ls -td [0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9]-[0-9][0-9][0-9][0-9][0-9][0-9] 2>/dev/null | head -n 1)

if [ -n "$LATEST_DIR" ] && [ -d "$LATEST_DIR" ]; then
  echo "최신 로그 디렉토리: $LATEST_DIR"
  
  if [ -f "$LATEST_DIR/pktgen_summary.log" ]; then
    echo "--- [pktgen_summary.log] ---"
    cat "$LATEST_DIR/pktgen_summary.log"
  fi
  
  if [ -f "$LATEST_DIR/ip.log" ]; then
    echo "--- [ip.log (일부 출력)] ---"
    head -n 25 "$LATEST_DIR/ip.log"
    echo "..."
  fi
else
  echo "생성된 로그 디렉토리를 찾을 수 없습니다."
fi

echo "테스트 완료!"
