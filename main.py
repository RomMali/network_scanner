from flask import Flask
from flask_jwt_extended import JWTManager
from backend.auth.routes import auth_bp
from backend.core.routes import core_bp
from backend.helpers.html_helper import html_generator

# Flask App Setup
app = Flask(__name__)

app.config["JWT_SECRET_KEY"] = "super-secret-key"  # Replace with a strong secret
jwt = JWTManager(app)

# Register Blueprints
app.register_blueprint(core_bp)
app.register_blueprint(auth_bp, url_prefix="/auth")

# Generating the HTML Dashboard
html_generator()

# --------------------- APP ENTRY POINT ----------------------

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True, threaded=True)
