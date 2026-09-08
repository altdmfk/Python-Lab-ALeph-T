import unittest
import json
from app import create_app
from config import Config
from extensions import db
from models import SecurityEvent


class TestConfig(Config):
    TESTING = True
    SQLALCHEMY_DATABASE_URI = 'sqlite:///:memory:'
    SECURITY_API_KEY = 'test-secret-key'
    AUTO_POST_ON_DENY = False


class SecurityAPITestCase(unittest.TestCase):
    def setUp(self):
        self.app = create_app(TestConfig)
        self.client = self.app.test_client()
        self.app_context = self.app.app_context()
        self.app_context.push()
        db.create_all()

    def tearDown(self):
        db.session.remove()
        db.drop_all()
        self.app_context.pop()

    def test_post_without_api_key_returns_401(self):
        """헤더에 X-API-Key가 없으면 401을 반환해야 함"""
        payload = {
            'student': '테스터',
            'src_ip': '1.2.3.4',
            'decision': 'deny'
        }
        res = self.client.post('/api/security/events',
                               data=json.dumps(payload),
                               content_type='application/json')
        self.assertEqual(res.status_code, 401)
        data = res.get_json()
        self.assertIn('API 키가 없거나 잘못되었습니다', data.get('msg', ''))

    def test_post_with_wrong_api_key_returns_401(self):
        """헤더에 잘못된 X-API-Key를 제공하면 401을 반환해야 함"""
        payload = {
            'student': '테스터',
            'src_ip': '1.2.3.4',
            'decision': 'deny'
        }
        res = self.client.post('/api/security/events',
                               headers={'X-API-Key': 'wrong-key'},
                               data=json.dumps(payload),
                               content_type='application/json')
        self.assertEqual(res.status_code, 401)

    def test_post_with_missing_required_fields_returns_400(self):
        """필수 필드(student, src_ip, decision) 누락 또는 잘못된 decision은 400을 반환해야 함"""
        headers = {'X-API-Key': 'test-secret-key'}
        res = self.client.post('/api/security/events',
                               headers=headers,
                               json={'src_ip': '1.2.3.4', 'decision': 'allow'})
        self.assertEqual(res.status_code, 400)

        res = self.client.post('/api/security/events',
                               headers=headers,
                               json={'student': '홍길동', 'decision': 'allow'})
        self.assertEqual(res.status_code, 400)

        res = self.client.post('/api/security/events',
                               headers=headers,
                               json={'student': '홍길동', 'src_ip': '1.2.3.4', 'decision': 'unknown'})
        self.assertEqual(res.status_code, 400)

    def test_post_event_success_creates_record_and_returns_201(self):
        """올바른 인증 및 페이로드 전송 시 201 생성 및 DB 저장 확인"""
        headers = {'X-API-Key': 'test-secret-key'}
        payload = {
            'student': '홍길동',
            'src_ip': '192.168.0.10',
            'fail_count': 5,
            'decision': 'deny',
            'severity': 'High',
            'reason': '비밀번호 5회 오류',
            'users': 'admin',
            'last_seen': '2026-09-08 12:00:00',
            'window_min': 10,
            'source': 'login_guard',
            'generated_at': '2026-09-08 12:00:00'
        }
        res = self.client.post('/api/security/events',
                               headers=headers,
                               json=payload)
        self.assertEqual(res.status_code, 201)
        data = res.get_json()
        self.assertIn('id', data)
        self.assertEqual(data['student'], '홍길동')
        self.assertEqual(data['decision'], 'deny')

        event = db.session.get(SecurityEvent, data['id'])
        self.assertIsNotNone(event)
        self.assertEqual(event.src_ip, '192.168.0.10')
        self.assertEqual(event.fail_count, 5)
        self.assertEqual(event.severity, 'High')
        self.assertEqual(event.reason, '비밀번호 5회 오류')

    def test_post_event_with_is_deny_field(self):
        """is_deny 필드가 True면 'deny', False면 'allow'로 자동 매핑되는지 검증"""
        headers = {'X-API-Key': 'test-secret-key'}

        # 1) is_deny: True -> decision: deny
        res1 = self.client.post('/api/security/events', headers=headers, json={
            'student': '테스터',
            'src_ip': '10.0.0.1',
            'is_deny': True
        })
        self.assertEqual(res1.status_code, 201)
        self.assertEqual(res1.get_json()['decision'], 'deny')

        # 2) is_deny: False -> decision: allow
        res2 = self.client.post('/api/security/events', headers=headers, json={
            'student': '테스터',
            'src_ip': '10.0.0.2',
            'is_deny': False
        })
        self.assertEqual(res2.status_code, 201)
        self.assertEqual(res2.get_json()['decision'], 'allow')

    def test_get_events_filtered_by_student_and_ordered_desc(self):
        """GET /api/security/events?student=<이름> 인증 없이 최신순 조회 검증"""
        e1 = SecurityEvent(student='홍길동', src_ip='1.1.1.1', fail_count=1, decision='allow')
        e2 = SecurityEvent(student='김철수', src_ip='2.2.2.2', fail_count=3, decision='deny')
        e3 = SecurityEvent(student='홍길동', src_ip='3.3.3.3', fail_count=6, decision='deny')
        db.session.add_all([e1, e2, e3])
        db.session.commit()

        res = self.client.get('/api/security/events?student=홍길동')
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertEqual(data['count'], 2)
        events = data['events']
        self.assertEqual(len(events), 2)
        
        self.assertEqual(events[0]['id'], e3.id)
        self.assertEqual(events[0]['src_ip'], '3.3.3.3')
        self.assertEqual(events[1]['id'], e1.id)
        self.assertEqual(events[1]['src_ip'], '1.1.1.1')
        
        for ev in events:
            self.assertEqual(ev['student'], '홍길동')


if __name__ == '__main__':
    unittest.main()
