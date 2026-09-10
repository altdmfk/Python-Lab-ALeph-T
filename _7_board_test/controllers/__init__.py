from .admin_controller import admin_bp
from .auth_controller import auth_bp
from .page_controller import page_bp
from .post_controller import post_bp
from .public_controller import public_bp
from .security_controller import security_bp

all_blueprints = (page_bp, auth_bp, post_bp, security_bp, public_bp, admin_bp)

__all__ = ['all_blueprints', 'page_bp', 'auth_bp', 'post_bp',
           'security_bp', 'public_bp', 'admin_bp']

