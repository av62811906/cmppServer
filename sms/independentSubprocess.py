import socket
import threading
import time

from settings import socketSettings
from sms import process
from decoder import baseStruct
from storages import redisStorage
from settings import redisSettings


def subprocess_main(server_conn: socket.socket, addr: tuple):
    """独立子进程主循环"""

    config = {'spid': None, 'addr': addr, 'virtual_code': '10690', 'residue': b'', 'break': False}  # 参数
    redis_log = redisStorage.CmppCache(redisSettings.REDIS_HOST, redisSettings.REDIS_PORT, redisSettings.LOGIN_LOG,
                                       redisSettings.REDIS_PASSWORD)  # 日志redis链接
    redis_submit = redisStorage.CmppSubmit(redisSettings.REDIS_HOST, redisSettings.REDIS_PORT, redisSettings.CMPP_SUBMIT_CACHE,
                                           redisSettings.REDIS_PASSWORD)  # submit redis 链接
    thm = threading.Thread(target=my_beat, args=(server_conn, config))  # 主动心跳
    thm.start()

    while True:

        """接收数据"""
        original_data = process.receive_data(server_conn, socketSettings.RECEIVE_BUFFER)
        print(original_data)

        """数据如果为空 或 break断链信号为True，则断链"""
        if original_data == b'' or config['break']:
            process.client_disconnect(addr, redis_log, redis_submit, config)
            break

        """拆包"""
        original_data_pool, config['residue'] = baseStruct.data_resolution(original_data, config['residue'])

        """解析数据"""
        process.analysis_original_data_pool(original_data_pool, addr, server_conn, redis_log, redis_submit, config)

        """从redis中取出response"""

        """发送response"""

        """从redis中取出状态报告"""

        """发送状态报告"""

        """从redis中取出上行"""

        """发送上行"""

    thm.join(timeout=1)


def my_beat(server_conn, config):
    """主动心跳"""

    while True:
        time.sleep(5)
        process.my_beat(server_conn=server_conn, config=config)