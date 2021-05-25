import socket
from multiprocessing import Pool

from storages import redisStorage
from settings import redisSettings
from sms import independentSubprocess


class SocketServer:

    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.server = None
        self.pool = Pool(processes=500)

    def listen(self):
        """创建socket server"""
        while True:
            # 创建socket
            server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            # 设置socket长连接
            server.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
            # 链接
            try:
                server.bind((self.host, self.port))
            except OSError:
                continue
            # 监听
            server.listen(1000)
            self.server = server
            break

    def accept(self):
        """接收链接请求"""
        conn, addr = self.server.accept()
        # 将数据链接地址写入redis
        redis_conn = redisStorage.SocketAcceptCache(redisSettings.REDIS_HOST, redisSettings.REDIS_PORT, redisSettings.ACCEPT_LOG,
                                                    redisSettings.REDIS_PASSWORD)
        redis_conn.connect(addr)
        redis_conn.close()
        # 创建新的子进程
        self.pool.apply_async(func=independentSubprocess.subprocess_main, args=(conn, addr,))