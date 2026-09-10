from extensions import db


class User(db.Model):
  __tablename__ = 'users'

  id = db.Column(db.Integer, primary_key=True)
  username = db.Column(db.String(80), unique=True, nullable=False)
  password = db.Column('password_hash', db.String(255), nullable=False)   # DB 컬럼: password_hash
  role = db.Column(db.Integer, nullable=False, default=0) # 0: 일반, 1: 골드, 2: 관리자


  @property
  def role_name(self):
    mapping = {0: '일반회원', 1: '골드회원', 2: '관리자'}
    return mapping.get(self.role, '일반회원')

  def to_dict(self):
    return {
        'id': self.id,
        'username': self.username,
        'role': self.role,
        'role_name': self.role_name,
    }

  def __repr__(self):
    return f'<User {self.username} (role={self.role})>'

