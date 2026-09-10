"""관리자 컨트롤러 — 회원 목록 조회, 등급 수정, 삭제 API.
권한: 관리자(role=2)만 호출 가능.
"""
from functools import wraps
from flask import Blueprint, jsonify, request
from flask_jwt_extended import get_jwt_identity, jwt_required
from extensions import db
from models import User

admin_bp = Blueprint('admin', __name__, url_prefix='/api/admin')


def admin_required(fn):
    """관리자(role == 2) 권한 체크 데코레이터"""
    @wraps(fn)
    @jwt_required()
    def wrapper(*args, **kwargs):
        uid = get_jwt_identity()
        user = db.session.get(User, int(uid))
        if not user or user.role < 2:
            return jsonify({
                'error': 'Forbidden',
                'msg': '관리자(등급 2) 전용 기능입니다. 접근 권한이 없습니다.',
                'current_role': user.role if user else None
            }), 403
        return fn(*args, **kwargs)
    return wrapper


@admin_bp.route('/users', methods=['GET'])
@admin_required
def list_users():
    """모든 회원 목록 조회"""
    users = User.query.order_by(User.id.asc()).all()
    return jsonify({
        'count': len(users),
        'users': [u.to_dict() for u in users]
    })


@admin_bp.route('/users/<int:user_id>', methods=['PUT'])
@admin_required
def update_user_role(user_id):
    """회원 등급 변경 (0: 일반, 1: 골드, 2: 관리자)"""
    user = db.session.get(User, user_id)
    if not user:
        return jsonify({'msg': '존재하지 않는 회원입니다.'}), 404

    data = request.get_json(silent=True) or {}
    new_role = data.get('role')

    if new_role is None or int(new_role) not in (0, 1, 2):
        return jsonify({'msg': '올바른 등급(0: 일반, 1: 골드, 2: 관리자)을 지정하세요.'}), 400

    user.role = int(new_role)
    db.session.commit()

    return jsonify({
        'msg': f'{user.username} 회원의 등급이 {user.role_name}({user.role})으로 변경되었습니다.',
        'user': user.to_dict()
    })


@admin_bp.route('/users/<int:user_id>', methods=['DELETE'])
@admin_required
def delete_user(user_id):
    """회원 삭제"""
    uid = get_jwt_identity()
    if int(uid) == user_id:
        return jsonify({'msg': '자기 자신(현재 로그인한 관리자 계정)은 삭제할 수 없습니다.'}), 400

    user = db.session.get(User, user_id)
    if not user:
        return jsonify({'msg': '존재하지 않는 회원입니다.'}), 404

    username = user.username
    db.session.delete(user)
    db.session.commit()

    return jsonify({'msg': f'{username} 회원이 정상적으로 삭제되었습니다.'})
