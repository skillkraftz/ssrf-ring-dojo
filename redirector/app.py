from flask import Flask, redirect, request

app = Flask(__name__)


@app.get("/bounce")
def bounce():
    target = request.args.get("to", "http://example.com")
    return redirect(target, code=302)


@app.get("/chain")
def chain():
    first = request.args.get("first", "http://example.com")
    second = request.args.get("second")
    if second:
        return redirect(f"/bounce?to={second}", code=307)
    return redirect(first, code=307)


@app.get("/to-admin-health")
def to_admin_health():
    return redirect("http://internal-admin:5001/health", code=302)


@app.get("/to-token-mint")
def to_token_mint():
    return redirect(
        "http://token-service:5003/mint?aud=internal-admin-export&service=internal-admin",
        code=302,
    )


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5002)
