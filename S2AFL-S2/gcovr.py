import http.server
import socketserver
import subprocess
import time
import threading

# 定义HTTP服务器端口
PORT = 8000

# 定义gcovr命令
GCOVR_COMMAND = "gcovr -r . --html --html-details -o index.html"

# 定义每10分钟执行一次gcovr的函数
def run_gcovr():
    while True:
        print("Running gcovr...")
        subprocess.run(GCOVR_COMMAND, shell=True, check=True)
        print("gcovr completed.")
        time.sleep(600)  # 10分钟

# 启动HTTP服务器
class ThreadedHTTPServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    pass

Handler = http.server.SimpleHTTPRequestHandler

with ThreadedHTTPServer(("", PORT), Handler) as httpd:
    print(f"Serving at port {PORT}")

    # 启动gcovr定时任务线程
    gcovr_thread = threading.Thread(target=run_gcovr)
    gcovr_thread.daemon = True  # 设置为守护线程，这样主线程结束时gcovr线程也会结束
    gcovr_thread.start()

    # 启动HTTP服务器
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("Server stopped by user.")