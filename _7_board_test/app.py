"""엔트리포인트 — 앱 팩토리(create_app) 패턴.

구조
  config.py       설정(.env 로딩)
  extensions.py   db · jwt 인스턴스
  models/         User · Post · SecurityEvent
  controllers/    page · auth · post · security · public (블루프린트)
  templates/      화면 (partials/_nav.html = 공통 반응형 헤더)

실행:  python app.py   →  http://localhost:5000
"""
from flask import Flask
from sqlalchemy import inspect, text

from config import Config
from controllers import all_blueprints
from extensions import db, jwt


def _ensure_schema():
  """기존 users 표에 role 관련 컬럼이 없으면 추가(가벼운 자동 마이그레이션).

  db.create_all() 은 '없는 표'만 만들고 '기존 표'는 손대지 않는다. 이미 운영 중인
  users 표에 role/감사 컬럼을 더하려면 ALTER 가 필요하므로, 여기서 컬럼 유무를
  검사해 없을 때만 한 번 추가한다(있으면 조용히 통과 — 여러 번 켜도 안전)."""
  cols = {c['name'] for c in inspect(db.engine).get_columns('users')}
  adds = {
      'role': "ALTER TABLE users ADD COLUMN role VARCHAR(20) NOT NULL DEFAULT 'user'",
      'role_granted_by': "ALTER TABLE users ADD COLUMN role_granted_by VARCHAR(80) NULL",
      'role_granted_at': "ALTER TABLE users ADD COLUMN role_granted_at DATETIME NULL",
      'role_reason': "ALTER TABLE users ADD COLUMN role_reason VARCHAR(200) NULL",
  }
  with db.engine.begin() as conn:
    for name, ddl in adds.items():
      if name not in cols:
        conn.execute(text(ddl))


def create_app(config_class=Config):
  app = Flask(__name__)
  app.config.from_object(config_class)

  # 확장 초기화
  db.init_app(app)
  jwt.init_app(app)

  # 컨트롤러(블루프린트) 등록
  for bp in all_blueprints:
    app.register_blueprint(bp)

  # 테이블 생성 (models 를 import 한 뒤여야 한다 — controllers 가 이미 import 함)
  with app.app_context():
    db.create_all()
    _ensure_schema()   # 기존 users 표에 role 컬럼 보강

  return app


app = create_app()


if __name__ == '__main__':
  # host='0.0.0.0' 이면 같은 공유기의 다른 기기에서도 접속 가능.
  # 도커 안 n8n 에서는 http://host.docker.internal:5000 으로 부른다.
  app.run(debug=True, host='0.0.0.0', port=5000)
