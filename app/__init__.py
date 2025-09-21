from flask import Flask
import os

def create_app():
    app = Flask(__name__, template_folder='../templates', static_folder='../static')
    
    # Simple Flask configuration
    app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev-secret-key-change-in-production')
    app.config['SESSION_TYPE'] = 'filesystem'
    
    from app.routes import main
    app.register_blueprint(main)
    
    return app