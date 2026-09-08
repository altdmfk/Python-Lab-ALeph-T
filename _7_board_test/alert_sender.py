"""과제 1 — 파이썬 전송기 (alert_sender.py)

n8n 워크플로우를 수정할 필요 없이,
경보 목록(alerts)의 데이터를 순서대로 1건씩 n8n Webhook으로 전송합니다.
"""
import os
import json
import time
import requests
from dotenv import load_dotenv

load_dotenv()

# ==============================================================================
# 설정 (환경변수 우선, 없으면 플레이스홀더)
# ==============================================================================
# n8n Webhook URL (환경변수 N8N_WEBHOOK_URL 또는 .env 에서 로드)
N8N_WEBHOOK_URL = os.environ.get(
    "N8N_WEBHOOK_URL",
    "http://localhost:5678/webhook/<your-webhook-id>"
)

# 본인 식별자 (채점 증적용 필수)
STUDENT_NAME = os.environ.get("STUDENT_NAME", "강아름")


# 전송할 경보 목록 (2건 이상, 거부(level >= 10)와 허용(level < 10) 모두 포함)
ALERTS_DATA = [
    {
        "ip": "192.168.1.100",
        "level": 12,       # 레벨 10 이상 -> 거부(deny) 대상
        "rule": "5710",
        "severity": "High",
        "message": "무차별 대입 공격 의심 (차단)"
    },
    {
        "ip": "192.168.1.101",
        "level": 5,        # 레벨 10 미만 -> 허용(allow) 대상
        "rule": "5715",
        "severity": "Low",
        "message": "일반 로그인 시도 (허용)"
    },
    {
        "ip": "10.0.0.55",
        "level": 10,       # 레벨 10 이상 -> 거부(deny) 대상
        "rule": "5720",
        "severity": "High",
        "message": "비인가 관리자 계정 접근 (차단)"
    }
]


def send_alerts(url=N8N_WEBHOOK_URL, student=STUDENT_NAME, alerts=ALERTS_DATA):
    """경보 목록을 화면에 보여주고, n8n이 바로 처리할 수 있도록 1건씩 순차 전송합니다."""
    # [A2 채점 증적] student 및 alerts 목록 화면 출력
    print("=" * 60)
    print("▶ [전송할 경보 목록 - Total:", len(alerts), "건]")
    print(json.dumps({"student": student, "alerts": alerts}, indent=2, ensure_ascii=False))
    print("=" * 60)

    success_count = 0

    for idx, alert in enumerate(alerts, start=1):
        # n8n 노드에서 $json.ip, $json.severity 등으로 바로 꺼내 쓸 수 있도록 1건씩 패키징
        payload = {
            "student": student,
            "ip": alert["ip"],
            "level": alert["level"],
            "rule": alert["rule"],
            "severity": alert.get("severity", "Low"),
            "message": alert.get("message", "보안 이벤트 감지"),
            "is_deny": alert["level"] >= 10   # 레벨 10 이상이면 True (deny)
        }

        print(f"\n[{idx}/{len(alerts)}] 전송 중... (IP: {alert['ip']}, Level: {alert['level']})")

        try:
            res = requests.post(
                url,
                json=payload,
                headers={"Content-Type": "application/json; charset=utf-8"},
                timeout=10
            )
            # [A1 증적] n8n 응답 출력
            print(f"[n8n] POST {url} -> {res.status_code}")
            if res.ok:
                success_count += 1
            if res.text:
                print(f"[n8n] 응답: {res.text.strip()}")

        except requests.exceptions.RequestException as e:
            # [A3 증적] 오류 발생 시 친절한 출력
            print(f"[n8n] 전송 실패 (서버 연결 불가): {e}")

        # 0.5초 간격으로 전송
        time.sleep(0.5)

    print("\n" + "=" * 60)
    print(f"전송 완료! (성공: {success_count}/{len(alerts)}건)")
    print("=" * 60)


if __name__ == "__main__":
    send_alerts()
