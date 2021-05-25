import json
import time

import redis

from settings import redisSettings


class BaseConnect:
    """redis基本类"""

    def __init__(self, host, port, db, password):
        self.host = host
        self.port = port
        self.db = db
        self.password = password
        self.conn = redis.StrictRedis(host, port, db, password)
        self.pipe = self.conn.pipeline(False)

    def execute(self):
        self.pipe.execute()

    def close(self):
        self.conn.close()


class SocketAcceptCache(BaseConnect):
    """socket接收链接缓存"""

    def __init__(self, host, port, db, password):
        super().__init__(host, port, db, password)

    def connect(self, addr: tuple):
        name = 'connect:' + str(addr[0])
        value = str(addr[1]) + ':' + time.asctime()
        self.conn.lpush(name, value)
        self.conn.ltrim(name, 0, redisSettings.ACCEPT_LOG_LIMIT_PER_USER)

    def disconnect(self, addr: tuple):
        name = 'disconnect:' + str(addr[0])
        value = str(addr[1]) + ':' + time.asctime()
        self.conn.lpush(name, value)
        self.conn.ltrim(name, 0, redisSettings.ACCEPT_LOG_LIMIT_PER_USER)


class CmppCache(BaseConnect):
    """cmpp 缓存"""

    def __init__(self, host, port, db, password):
        super().__init__(host, port, db, password)

    def log_push(self, name, value):
        self.pipe.lpush(name, value)
        self.pipe.ltrim(name, 0, redisSettings.ACCEPT_LOG_LIMIT_PER_USER)

    def login_cache(self, original_data, sequence_id, source_addr, version, timestamp, result, addr):
        """缓存登录日志"""
        name = 'login:' + str(source_addr)
        value = f'sequence_id:{str(sequence_id)};version:{str(version)};timestamp:{str(timestamp)};result:{str(result)};original_data:{str(original_data)};addr:{str(addr)};time:{time.asctime()}'
        self.log_push(name, value)

    def login_resp_cache(self, original_data, sequence_id, source_addr, status, shared_secret, version, authenticatorISMG, addr):
        """缓存登录resp日志"""
        name = 'login_resp:' + str(source_addr)
        value = f'sequence_id:{str(sequence_id)};status:{str(status)};shared_secret:{str(shared_secret)};version:{str(version)};authenticatorISMG:{str(authenticatorISMG)};original_data:{str(original_data)};addr:{str(addr)};time:{time.asctime()}'
        self.log_push(name, value)

    def online(self, source_addr):
        """设置为登录状态"""
        self.conn.zadd('online:', {str(source_addr): time.time()})

    def offline(self, source_addr):
        """设置下线状态"""
        self.conn.zrem('online:', str(source_addr))

    def is_online(self, source_addr):
        """检查用户是否为已登录状态"""
        res = self.conn.zscore('online:', str(source_addr))
        return True if res else False

    def active_test_cache(self, original_data, sequence_id, source_addr, reserve, addr):
        """缓存心跳日志"""
        name = 'active_test:' + str(source_addr)
        value = f'sequence_id:{str(sequence_id)};reserve:{str(reserve)};addr:{str(addr)};original_data:{str(original_data)};time:{time.asctime()}'
        self.log_push(name, value)

    def active_test_resp_cache(self, original_data, sequence_id, source_addr, addr):
        name = 'active_test_resp:' + str(source_addr)
        value = f'sequence_id:{str(sequence_id)};addr:{str(addr)};original_data:{str(original_data)};time:{time.asctime()}'
        self.log_push(name, value)

    def submit_cache(self, original_data, addr, source_addr, data):
        """缓存submit"""
        name = 'submit:' + str(source_addr)
        value = f'data:{str(data)};addr:{str(addr)};original_data{str(original_data)};time:{time.asctime()}'


class CmppSubmit(BaseConnect):
    """cmpp 信息提交入库"""

    def __init__(self, host, port, db, password):
        super().__init__(host, port, db, password)

    def submitSave(self, source_addr, data):
        self.pipe.zadd('submit:' + str(source_addr), {json.dumps(data, ensure_ascii=False): time.time()})
