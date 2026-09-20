import os

from flask import Flask
from flask_jwt_extended import JWTManager
from backend.auth.routes import auth_bp
from backend.core.routes import core_bp

app = Flask(__name__)
app.config["JWT_SECRET_KEY"] = os.environ.get("JWT_SECRET_KEY", "dev-only-change-me")
app.config["JWT_TOKEN_LOCATION"] = ["headers"]
jwt = JWTManager(app)

app.register_blueprint(core_bp)
app.register_blueprint(auth_bp, url_prefix="/auth")


if __name__ == "__main__":
    host = os.environ.get("FLASK_HOST", "127.0.0.1")
    app.run(host=host, port=int(os.environ.get("FLASK_PORT", "5000")), debug=False, threaded=True)
