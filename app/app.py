import os
import requests
from flask import Flask, request

app = Flask(__name__)

# 환경변수에서 역할을 가져옴 (기본값: backend)
ROLE = os.getenv('ROLE', 'backend')
# 백엔드 주소 (쿠버네티스 서비스 이름 예정)
BACKEND_URL = os.getenv('BACKEND_URL', 'http://backend')

@app.route('/')
def home():
    if ROLE == 'frontend':
        try:
            # 프론트엔드면 백엔드를 호출함
            response = requests.get(BACKEND_URL, timeout=5)
            return f"<h1>Frontend says:</h1> <p>Backend replied: {response.text}</p>"
        except Exception as e:
            return f"<h1>Frontend Error:</h1> <p>Could not reach backend. Reason: {e}</p>"
    else:
        # 백엔드면 그냥 메시지 리턴
        return "Hello from Backend! (I am the secret data)"

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080)