"""관리자(인가/RBAC) REST — 회원 권한 부여·회수.

접근 방식 두 가지
  ① 기계 호출(n8n·회수봇)  : 헤더  X-API-Key: <ADMIN_API_KEY>
  ② 사람(관리자 페이지)     : JWT(로그인 토큰) + 그 계정의 role == 'admin'

시나리오
  - 관리자 페이지에서 특정 회원에게 admin 을 '부여'(인가) → 불필요한 과잉권한 발생
  - 파이썬 회수봇이 허용목록(ADMIN_ALLOWLIST) 밖 admin 을 탐지 → Graylog 신고
  - Graylog 이벤트 → n8n → 이 API 의 /revoke 를 호출해 실제 '회수'(최소권한 복원)
  - 회수 시 security_events 에 감사기록(source='privilege-guard') → 대시보드 노출
"""
from datetime import datetime
from functools import wraps

from flask import Blueprint, current_app, jsonify, request

from extensions import db
from models import SecurityEvent, User

from .rbac import VALID_ROLES, current_user   # 등급 정의는 rbac 한 곳에서

admin_bp = Blueprint('admin', __name__, url_prefix='/api/admin')

# ('user', 'gold', 'admin') — models/user.py 의 ROLE_LEVEL 에서 온다.
ROLE_CHOICES = '|'.join(VALID_ROLES)


def _has_valid_key():
  """X-API-Key 가 ADMIN_API_KEY 와 일치하면 True(비어 있으면 항상 False = fail-closed)."""
  expected = current_app.config.get('ADMIN_API_KEY', '')
  return bool(expected) and request.headers.get('X-API-Key', '') == expected


def _current_admin_user():
  """JWT 가 있고 그 계정이 admin 이면 User, 아니면 None."""
  user = current_user()
  return user if (user and user.is_admin) else None


def admin_required(fn):
  """유효한 관리자 키(기계) 또는 admin JWT(사람)면 통과. 아니면 401/403."""
  @wraps(fn)
  def wrapper(*args, **kwargs):
    if _has_valid_key():
      request.actor = 'apikey'
      return fn(*args, **kwargs)
    admin = _current_admin_user()
    if admin:
      request.actor = admin.username
      return fn(*args, **kwargs)
    return jsonify({'msg': '관리자 인가가 필요합니다(X-API-Key 또는 admin 로그인).'}), 401
  return wrapper


def _allowlist(param=None):
  """정책 허용목록. 쿼리/바디로 넘기면 우선, 없으면 config(.env)."""
  if param:
    return [u.strip() for u in param.split(',') if u.strip()]
  return current_app.config.get('ADMIN_ALLOWLIST', [])


@admin_bp.route('/users', methods=['GET'])
@admin_required
def list_users():
  """회원 목록 + 역할. ?role=admin 으로 필터."""
  role = request.args.get('role')
  q = User.query
  if role in VALID_ROLES:
    q = q.filter_by(role=role)
  rows = q.order_by(User.id.asc()).all()
  return jsonify({'count': len(rows), 'users': [u.to_dict() for u in rows]})


@admin_bp.route('/violations', methods=['GET'])
@admin_required
def list_violations():
  """정책 위반(허용목록 밖 admin) 목록. 회수봇이 참고용으로 쓸 수 있다.
  ?allowlist=lsy,instructor 로 기준을 넘기면 그걸 우선 적용."""
  allow = _allowlist(request.args.get('allowlist'))
  admins = User.query.filter_by(role='admin').all()
  bad = [u for u in admins if u.username not in allow]
  return jsonify({
      'allowlist': allow,
      'count': len(bad),
      'violations': [u.to_dict() for u in bad],
  })


@admin_bp.route('/grant', methods=['POST'])
@admin_required
def grant_role():
  """회원에게 역할 부여(인가). body: {username, role, reason}
  시나리오상 여기서 admin 을 잘못/과하게 부여해 '불필요한 권한'을 만든다."""
  data = request.get_json(silent=True) or {}
  username = (data.get('username') or '').strip()
  role = (data.get('role') or '').strip()
  if not username or role not in VALID_ROLES:
    return jsonify({'msg': f'username, role({ROLE_CHOICES}) 은 필수입니다.'}), 400

  user = User.query.filter_by(username=username).first()
  if not user:
    return jsonify({'msg': f'없는 사용자: {username}'}), 404

  old = user.role
  user.role = role
  user.role_granted_by = getattr(request, 'actor', 'unknown')
  user.role_granted_at = datetime.now()
  user.role_reason = (data.get('reason') or '')[:200]
  db.session.commit()
  return jsonify({'msg': '역할 부여 완료', 'username': username,
                  'old_role': old, 'new_role': role,
                  'granted_by': user.role_granted_by}), 200


@admin_bp.route('/revoke', methods=['POST'])
@admin_required
def revoke_role():
  """과잉권한 회수(최소권한 복원) → role 을 'user' 로. n8n 이 호출.
  body: {username, reason, student, severity, src_ip}
  회수가 실제로 일어나면 security_events 에 감사기록(source='privilege-guard')을 남긴다."""
  data = request.get_json(silent=True) or {}
  username = (data.get('username') or '').strip()
  if not username:
    return jsonify({'msg': 'username 은 필수입니다.'}), 400

  user = User.query.filter_by(username=username).first()
  if not user:
    return jsonify({'msg': f'없는 사용자: {username}'}), 404

  old = user.role
  actor = getattr(request, 'actor', 'unknown')
  if old == 'user':
    # 이미 최소권한 — 변경 없음(감사기록도 남기지 않아 소음 방지)
    return jsonify({'msg': '이미 user 권한(회수 불필요)', 'username': username,
                    'old_role': old, 'new_role': 'user', 'revoked': False}), 200

  user.role = 'user'
  user.role_granted_by = actor
  user.role_granted_at = datetime.now()
  user.role_reason = (data.get('reason') or f'{old}→user 회수 by {actor}')[:200]

  # 감사기록: 대시보드에서 보이도록 security_events 재사용
  ev = SecurityEvent(
      student=(data.get('student') or actor)[:50],
      src_ip=data.get('src_ip') or '0.0.0.0',
      fail_count=0, decision='deny',
      severity=data.get('severity', 'High'),
      reason=(data.get('reason') or f'과잉권한 회수: {username} {old}→user')[:200],
      users=username, source=data.get('source', 'privilege-guard'),
      generated_at=data.get('generated_at'),
  )
  db.session.add(ev)
  db.session.commit()
  return jsonify({'msg': '권한 회수 완료', 'username': username,
                  'old_role': old, 'new_role': 'user', 'revoked': True,
                  'event_id': ev.id, 'revoked_by': actor}), 200
