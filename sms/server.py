from socketPack import socketServer
from settings import socketSettings


def main():
    """主逻辑"""

    """创建socket监听"""
    socket_server = socketServer.SocketServer(socketSettings.LISTENING_HOST, socketSettings.LISTENING_PORT)
    socket_server.listen()
    while True:
        socket_server.accept()
