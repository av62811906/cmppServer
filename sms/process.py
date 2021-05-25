import socket

from storages import redisStorage
from settings import redisSettings, cmppCommandId
from decoder import dataStruct


def receive_data(server_conn: socket.socket, recv_buffer):
    """接收数据"""
    return server_conn.recv(recv_buffer)


def client_disconnect(addr, redis_log, redis_submit, config):
    """客户端断链"""
    redis_conn = redisStorage.SocketAcceptCache(redisSettings.REDIS_HOST, redisSettings.REDIS_PORT, redisSettings.ACCEPT_LOG,
                                                redisSettings.REDIS_PASSWORD)
    redis_conn.disconnect(addr)
    redis_conn.close()
    redis_log.offline(config['spid'])
    redis_submit.close()


def analysis_original_data_pool(original_data_pool, addr, server_conn, redis_log, redis_submit: redisStorage.CmppSubmit, config):
    """解析原始data消息池"""

    for original_data in original_data_pool:
        command_id = dataStruct.get_command_id(original_data)
        if command_id == int(cmppCommandId.CMPP_CONNECT_REQ):
            # 登录
            login(original_data, addr, server_conn, redis_log, config)
        elif command_id == int(cmppCommandId.CMPP_ACTIVE_TEST_REQ):
            # 心跳
            beat(original_data, addr, server_conn, redis_log, config)
        elif command_id == int(cmppCommandId.CMPP_ACTIVE_TEST_RESP):
            # 心跳回执
            follow_my_heart(original_data, addr, redis_log, config)
        elif command_id == int(cmppCommandId.CMPP_SUBMIT_REQ):
            # 发送信息
            receive(original_data, addr, redis_log, redis_submit, config)

    # submit写入redis
    redis_submit.execute()
    redis_log.execute()


def login(original_data, addr, server_conn: socket.socket, redis_log: redisStorage.CmppCache, config):
    """用户登录"""
    # 创建登录对象
    connect_obj = dataStruct.CmppConnectReqParser(original_data, addr)
    # 解析
    original_data, source_addr, version, timestamp, sequence_id = connect_obj.parse()
    # ip校验
    hflag = connect_obj.auth_host()
    # 用户信息校验
    aflag = connect_obj.auth()
    # 校验结果
    login_res = True if hflag and aflag else False
    # 返回信息给client
    resp, shared_secret, authenticatorISMG = connect_obj.response(0) if login_res else connect_obj.response(1)
    server_conn.send(resp)
    # 修改线程保存的spid
    config['spid'] = source_addr
    # 查找用户接入码
    config['virtual_code'] = connect_obj.find_virtual_code()
    # 修改为在线状态
    redis_log.online(source_addr)
    # 写入日志
    redis_log.login_cache(original_data, sequence_id, source_addr, version, timestamp, login_res, addr)
    redis_log.login_resp_cache(resp, sequence_id, source_addr, version, shared_secret, version, authenticatorISMG, addr)
    # 修改配置信息，登录失败则断链
    config['break'] = not login_res


def logged(config):
    """检查是否已登录"""
    # 检查
    cache_obj = redisStorage.CmppCache(redisSettings.REDIS_HOST, redisSettings.REDIS_PORT, redisSettings.LOGIN_LOG, redisSettings.REDIS_PASSWORD)
    res = cache_obj.is_online(config['spid'])
    return res


def beat(original_data, addr, server_conn: socket.socket, redis_log: redisStorage.CmppCache, config):
    """链路检测"""
    # 创建链路检测对象
    active_test_obj = dataStruct.CmppActiveTestParser(original_data)
    # 解析
    sequence_id = active_test_obj.parse()
    # 返回active test resp 给 client
    resp, reserve = active_test_obj.response()
    server_conn.send(resp)
    # 写入日志
    redis_log.active_test_cache(original_data, sequence_id, config['spid'], reserve, addr)


def my_beat(server_conn: socket.socket, config):
    """主动链路检测"""
    # 创建检测对象
    active_obj = dataStruct.CmppActiveTestParser(None)
    # 发送心跳检测
    beat_req = active_obj.beat()
    try:
        server_conn.send(beat_req)
    except BrokenPipeError:
        config['break'] = True


def follow_my_heart(original_data, addr, redis_log: redisStorage.CmppCache, config):
    """主动链路检测回执"""
    # 创建检测对象
    active_obj = dataStruct.CmppActiveTestParser(original_data)
    # 解析
    sequence_id = active_obj.parse()
    # 写入日志
    redis_log.active_test_resp_cache(original_data, sequence_id, config['spid'], addr)


def receive(original_data, addr, redis_log: redisStorage.CmppCache, redis_submit: redisStorage.CmppSubmit,
            config):
    """接收发送请求"""
    # 创建submit对象
    submit_obj = dataStruct.CmppSubmitParser(original_data)
    # 解析
    submit_obj.parse()
    # 格式构建
    json_data = submit_obj.json_construct(config)
    # 写入redis
    redis_submit.submitSave(config['spid'], json_data)
    # 写入日志
    redis_log.submit_cache(original_data, addr, config['spid'], json_data)
