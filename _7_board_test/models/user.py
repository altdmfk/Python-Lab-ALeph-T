from datetime import datetime

from extensions import db

# ── 등급 정의 ── 새 등급을 만들려면 이 두 표에만 추가하면 된다.
# 숫자가 클수록 높은 등급이고, 판정은 '같거나 높으면 통과'다.
ROLE_LEVEL = {'user': 1, 'gold': 2, 'admin': 3}
ROLE_LABEL = {'user': '일반', 'gold': '골드', 'admin': '관리자'}
VALID_ROLES = tuple(ROLE_LEVEL)


def role_level(role):
  """모르는 값은 0(권한 없음)으로 떨어뜨린다 — 안전한 쪽으로 실패한다."""
  return ROLE_LEVEL.get(role, 0)


class User(db.Model):
  __tablename__ = 'users'

  id = db.Column(db.Integer, primary_key=True)
  username = db.Column(db.String(80), unique=True, nullable=False)
  password = db.Column(db.String(255), nullable=False)   # 해시만 저장(평문 금지)

  # ── 인가(authorization) ── 역할 기반 접근제어(RBAC)
  # 'user'(기본) | 'gold' | 'admin'. 등급은 계단식이다(user < gold < admin).
  #   gold  : 골드 전용 화면(/gold) 이용
  #   admin : 관리자 페이지·회원 권한 관리 (골드 화면도 볼 수 있다)
  role = db.Column(db.String(20), nullable=False, default='user', server_default='user')
  # 감사(audit): 누가·언제·왜 이 권한을 부여/변경했는가
  role_granted_by = db.Column(db.String(80))
  role_granted_at = db.Column(db.DateTime)
  role_reason = db.Column(db.String(200))

  @property
  def is_admin(self):
    return self.role == 'admin'

  @property
  def is_gold(self):
    """골드 화면을 볼 수 있는가 — admin 도 True(등급이 더 높으므로)."""
    return self.has_role('gold')

  def has_role(self, required):
    """내 등급이 required 이상인가. user < gold < admin."""
    return role_level(self.role) >= role_level(required)

  def to_dict(self):
    return {
        'id': self.id,
        'username': self.username,
        'role': self.role,
        'role_granted_by': self.role_granted_by,
        'role_granted_at': (self.role_granted_at.isoformat()
                            if self.role_granted_at else None),
        'role_reason': self.role_reason,
    }

  def __repr__(self):
    return f'<User {self.username} ({self.role})>'
