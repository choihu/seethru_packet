#!/usr/bin/env python3
import argparse
import html
import http.cookies
from http.server import ThreadingHTTPServer, SimpleHTTPRequestHandler
from pathlib import Path
from urllib.parse import parse_qs
import os
import time

class SizeAwareHandler(SimpleHTTPRequestHandler):
    password: str | None = None

    def do_GET(self):
        if self.password and not self._is_authenticated():
            self._send_login_form()
            return
        super().do_GET()

    def do_POST(self):
        if self.path != "/login":
            self.send_error(404)
            return
        length = int(self.headers.get("Content-Length", "0") or 0)
        body = self.rfile.read(length).decode("utf-8")
        posted = parse_qs(body)
        submitted = posted.get("password", [""])[0]
        if submitted == (self.password or ""):
            self.send_response(303)
            self.send_header("Location", "/")
            cookie = http.cookies.SimpleCookie()
            cookie["AuthToken"] = submitted
            cookie["AuthToken"]["path"] = "/"
            cookie["AuthToken"]["httponly"] = True
            self.send_header("Set-Cookie", cookie.output(header=""))
            self.end_headers()
        else:
            self._send_login_form(error="잘못된 비밀번호입니다.")

    def list_directory(self, path):
        entries = sorted(Path(path).iterdir(), key=lambda p: p.name.lower())
        rows = []
        if self.path != "/":
            parent = "/".join(self.path.rstrip("/").split("/")[:-1]) or "/"
            rows.append(
                "<tr><td><a href='{0}'>..</a></td><td></td><td></td></tr>".format(
                    html.escape(parent)
                )
            )
        for entry in entries:
            stat = entry.stat()
            size = stat.st_size
            if entry.is_dir():
                size_text = "-"
                name = entry.name + "/"
            else:
                if size >= 1 << 30:
                    size_text = f"{size/(1<<30):.2f} GB"
                elif size >= 1 << 20:
                    size_text = f"{size/(1<<20):.2f} MB"
                elif size >= 1 << 10:
                    size_text = f"{size/(1<<10):.2f} KB"
                else:
                    size_text = f"{size} B"
                name = entry.name
            rows.append(
                "<tr>"
                f"<td><a href='{html.escape(entry.name)}'>{html.escape(name)}</a></td>"
                f"<td>{size_text}</td>"
                f"<td>{self.date_time_string(stat.st_mtime)}</td>"
                "</tr>"
            )

        page = f"""<!DOCTYPE html>
<html lang="ko"><head>
<meta charset="utf-8">
<title>Index of {html.escape(self.path)}</title>
<style>
body {{ font-family: sans-serif; }}
table {{ border-collapse: collapse; width: 100%; max-width: 960px; }}
th, td {{ border-bottom: 1px solid #ddd; padding: 6px 10px; text-align: left; }}
th {{ background: #f3f3f3; }}
</style>
</head><body>
<h2>Index of {html.escape(self.path)}</h2>
<table>
<thead><tr><th>이름</th><th>크기</th><th>수정 시각</th></tr></thead>
<tbody>
{''.join(rows)}
</tbody></table>
</body></html>"""

        encoded = page.encode("utf-8", "surrogateescape")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)
        return None

    # ----- 로그인 관련 보조 메서드 -----
    def _is_authenticated(self) -> bool:
        if not self.password:
            return True
        cookie_header = self.headers.get("Cookie", "")
        cookies = http.cookies.SimpleCookie()
        cookies.load(cookie_header)
        token = cookies.get("AuthToken")
        return token and token.value == self.password

    def _send_login_form(self, error: str | None = None):
        msg = "<p>목록을 보려면 비밀번호를 입력하세요.</p>"
        if error:
            msg = f"<p style='color:red;'>{html.escape(error)}</p>"
        body = f"""<!doctype html>
<html lang="ko"><head>
<meta charset="utf-8">
<title>로그인</title></head>
<body>
<h2>로그</h2>
{msg}
<form method="post" action="/login">
    <label>비밀번호: <input type="password" name="password" autofocus></label>
    <button type="submit">확인</button>
</form>
</body></html>"""
        data = body.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="간단한 로그 뷰어 서버")
    parser.add_argument("-p", "--port", type=int, default=14284, help="리슨할 포트 (기본 14284)")
    parser.add_argument("--bind", default="", metavar="ADDR", help="바인드할 주소 (기본 전체)")
    parser.add_argument("--password", default="tkdlqj1@#", help="로그 목록을 보호할 간단한 비밀번호")
    args = parser.parse_args()

    SizeAwareHandler.password = args.password

    server = ThreadingHTTPServer((args.bind, args.port), SizeAwareHandler)
    print(f"Serving on http://{args.bind or '127.0.0.1'}:{args.port}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down...")
        server.server_close()