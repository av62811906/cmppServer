import hashlib

from commons import commons
from decoder import baseStruct
from storages import mysqlStorage
from settings import mysqlSettings, cmppCommandId


def get_command_id(original_data):
    """获取消息头中的command id"""
    try:
        command_id = baseStruct.unpack_4_unsigned_integer(original_data[4: 8])[0]
    except:
        command_id = None

    return command_id


class DataParser:
    """解析方法"""

    def __init__(self, original_data):
        self.original_data = original_data
        self.total_length = None
        self.command_id = None
        self.sequence_id = None
        self.error = None

    def header_parse(self):
        try:
            self.total_length = baseStruct.unpack_4_unsigned_integer(self.original_data[0: 4])[0]
            self.command_id = baseStruct.unpack_4_unsigned_integer(self.original_data[4: 8])[0]
            self.sequence_id = baseStruct.unpack_4_unsigned_integer(self.original_data[8: 12])[0]
        except Exception:
            pass

    def header_construct(self, total_length, command_id, sequence_id):
        try:
            _total_length = baseStruct.pack_4_unsigned_integer(total_length)
            _command_id = baseStruct.pack_4_unsigned_integer(command_id)
            _sequence_id = baseStruct.pack_4_unsigned_integer(sequence_id)
        except Exception:
            _total_length, _command_id, _sequence_id = None, None, None
        return _total_length + _command_id + _sequence_id


class CmppConnectReqParser(DataParser):
    """cmpp链接"""

    def __init__(self, original_data, addr):
        super().__init__(original_data)
        self.source_addr = None
        self.authenticator_source = None
        self.version = None
        self.timestamp = None
        self.host = addr[0]
        self.port = addr[1]
        self.shared_secret = None

    def parse(self):
        """解析"""
        try:
            self.header_parse()
            self.source_addr = self.original_data[12: 18].decode('utf-8')
            self.authenticator_source = self.original_data[18: 34]
            self.version = baseStruct.unpack_1_unsigned_integer(self.original_data[34: 35])[0]
            self.timestamp = baseStruct.unpack_4_unsigned_integer(self.original_data[-4:])[0]
        except Exception:
            pass
        return self.original_data, self.source_addr, self.version, self.timestamp, self.sequence_id

    def auth_host(self):
        """校验ip"""
        mysql = mysqlStorage.Base(mysqlSettings.HOST, mysqlSettings.USER, mysqlSettings.PASSWORD, mysqlSettings.DATABASE)
        res = mysql.select_one(f'select ip from sms_customer where cus_name="{self.source_addr}"')
        return True if self.host in [x for x in res.split(',')] else False

    def auth(self):
        """校验"""
        source_addr = self.source_addr.encode('utf-8')
        shared_secret = self.find_shared_secret(source_addr).encode('utf-8')
        timestamp = str(self.timestamp)
        if len(timestamp) < 10:
            timestamp = (10 - len(timestamp)) * '0' + timestamp
        # 校验
        flag = True if self.authenticator_source == self.md5_digest(
            source_addr + 9 * b'\x00' + shared_secret + timestamp.encode('utf-8')) else False
        return flag

    def find_shared_secret(self, source_addr):
        """查找密码"""
        mysql = mysqlStorage.Base(mysqlSettings.HOST, mysqlSettings.USER, mysqlSettings.PASSWORD, mysqlSettings.DATABASE)
        self.shared_secret = mysql.select_one(sql=r'select cus_pwd from sms_customer where cus_name="%s"' % source_addr.decode('utf-8'))
        mysql.close()
        return self.shared_secret if self.shared_secret else ''

    def md5_digest(self, source_data):
        """md5加密"""
        return hashlib.md5(source_data).digest()

    def find_virtual_code(self):
        """查找接入码"""
        mysql = mysqlStorage.Base(mysqlSettings.HOST, mysqlSettings.USER, mysqlSettings.PASSWORD, mysqlSettings.DATABASE)
        virtual_code = mysql.select_one(sql=r'select virtual_code from sms_customer where cus_name="%s"' % self.source_addr)
        mysql.close()
        return virtual_code

    def response(self, status):
        """登录response"""
        _status = baseStruct.pack_1_unsigned_integer(status)
        _shared_secret = self.shared_secret
        _version = baseStruct.pack_1_unsigned_integer(self.version)
        _authenticatorISMG = self.md5_digest(_status + b'\x00' + b'')
        _message_body = _status + _authenticatorISMG + _version
        _total_length = 12 + len(_message_body)
        _command_id = cmppCommandId.CMPP_CONNECT_RESP
        _message_header = self.header_construct(_total_length, _command_id, self.sequence_id)
        return _message_header + _message_body, _shared_secret, _authenticatorISMG


class CmppActiveTestParser(DataParser):
    """链路检测"""

    def __init__(self, original_data):
        super().__init__(original_data)
        self.beat_id = 0

    def parse(self):
        """解析"""
        try:
            self.header_parse()
        except Exception:
            pass
        return self.sequence_id

    def response(self):
        """心跳response"""
        _reserve = b'\x00'
        _message_body = _reserve
        _total_length = len(_message_body) + 12
        _command_id = cmppCommandId.CMPP_CONNECT_RESP
        _sequence_id = self.sequence_id
        _message_header = self.header_construct(_total_length, _command_id, _sequence_id)
        return _message_header + _message_body, _reserve

    def beat(self):
        """主动心跳"""
        self.beat_id = commons.sequence_id_gen(self.beat_id)
        msg_header = self.header_construct(12, cmppCommandId.CMPP_ACTIVE_TEST_REQ, self.beat_id)
        msg_body = b''
        return msg_header + msg_body


class CmppSubmitParser(DataParser):
    """发送信息"""

    def __init__(self, original_data):
        super().__init__(original_data)
        self.original_data = original_data
        self.msg_id = None
        self.pk_total = None
        self.pk_number = None
        self.registered_delivery = None
        self.msg_level = None
        self.service_id = None
        self.fee_user_type = None
        self.fee_terminal_id = None
        self.tp_pid = None
        self.tp_udhi = None
        self.msg_fmt = None
        self.msg_src = None
        self.fee_type = None
        self.fee_code = None
        self.valid_time = None
        self.at_time = None
        self.src_id = None
        self.destusr_tl = None
        self.dest_terminal_id = None
        self.msg_length = None
        self.msg_content = None
        self.reserve = None
        self.xx = None
        self.mm = None
        self.nn = None

    def __str__(self):
        return f'total_length:{self.total_length};command_id:{self.command_id};sequence_id:{self.sequence_id};msg_id:{self.msg_id};pk_total:{self.pk_total};pk_number:{self.pk_number};registered_delivery:{self.registered_delivery};msg_level:{self.msg_level};service_id:{self.service_id};fee_user_type:{self.fee_user_type};fee_terminal_id:{self.fee_terminal_id};tp_pid:{self.tp_pid};tp_udhi:{self.tp_udhi};msg_fmt:{self.msg_fmt};msg_src:{self.msg_src};fee_type:{self.fee_type};fee_code:{self.fee_code};valid_time:{self.valid_time};at_time:{self.at_time};src_id:{self.src_id};destusr_tl:{self.destusr_tl};dest_terminal_id:{self.dest_terminal_id};msg_length:{self.msg_length};msg_content:{self.msg_content};reserve:{self.reserve}'

    def parse(self):
        """解析"""
        try:
            self.header_parse()
            _message_body = self.original_data[12:]
            self.msg_id = baseStruct.unpack_8_unsigned_integer(_message_body[0: 8])[0]
            self.pk_total = baseStruct.unpack_1_unsigned_integer(_message_body[8: 9])[0]
            self.pk_number = baseStruct.unpack_1_unsigned_integer(_message_body[9: 10])[0]
            self.registered_delivery = baseStruct.unpack_1_unsigned_integer(_message_body[10: 11])[0]
            self.msg_level = baseStruct.unpack_1_unsigned_integer(_message_body[11: 12])[0]
            self.service_id = _message_body[12: 22].decode('utf-8').rstrip('\x00')
            self.fee_user_type = baseStruct.unpack_1_unsigned_integer(_message_body[22: 23])[0]
            self.fee_terminal_id = _message_body[23: 44].decode('utf-8').rstrip('\x00')
            self.tp_pid = baseStruct.unpack_1_unsigned_integer(_message_body[44: 45])[0]
            self.tp_udhi = baseStruct.unpack_1_unsigned_integer(_message_body[45: 46])[0]
            self.msg_fmt = baseStruct.unpack_1_unsigned_integer(_message_body[46: 47])[0]
            self.msg_src = _message_body[47: 53].decode('utf-8')
            self.fee_type = _message_body[53: 55].decode('utf-8')
            self.fee_code = _message_body[55: 61].decode('utf-8')
            self.valid_time = _message_body[61: 78].decode('utf-8').rstrip('\x00')
            self.at_time = _message_body[78: 95].decode('utf-8').rstrip('\x00')
            self.src_id = _message_body[95: 116].decode('utf-8').rstrip('\x00')
            self.destusr_tl = baseStruct.unpack_1_unsigned_integer(_message_body[116: 117])[0]
            self.dest_terminal_id = _message_body[117: 138].decode('utf-8').rstrip('\x00')
            self.msg_length = baseStruct.unpack_1_unsigned_integer(_message_body[138: 139])[0]
            # 编码
            if self.msg_fmt == 8:
                self.msg_content = _message_body[139: -8].decode('utf-16-be')
            elif self.msg_fmt == 15:
                try:
                    _msg_content = _message_body[139: -8].decode('gbk')
                except Exception as e:
                    self.msg_content = _message_body[139: -8].decode('gb2312')
            elif self.msg_fmt == 0:
                self.msg_content = _message_body[139: -8].decode()
            else:
                _msg_content = b''
            self.reserve = _message_body[-8:].decode('utf-8').rstrip('\x00')
            # 长短信
            if self.tp_udhi == 1:
                protocol = self.find_xxmmnn(self.msg_content)
                self.msg_content = self.msg_content[int(protocol / 2):]
        except Exception:
            self.error = 'parse error'

    def find_xxmmnn(self, msg_content):
        """解析长短信xxmmnn"""
        # 获取原始编码串
        original_code = msg_content.encode('utf-16-be')
        # 获取前7个byte
        bt1, bt2, bt3, bt4, bt5, bt6, bt7 = original_code[0], original_code[1], original_code[2], original_code[3], original_code[4], \
                                            original_code[5], original_code[6]
        # 通过byte1判断为几位协议
        protocol_type = 6 if bt1 == 5 else 7
        # 根据协议类型返回信息
        # {'xx': 108, 'mm': 2, 'nn': 1} xx: 唯一标识 mm: 该批短信数量 nn: 当前值
        if protocol_type == 6:
            self.xx, self.mm, self.nn = bt4, bt5, bt6
        else:
            self.xx, self.mm, self.nn = int(str(bt4) + str(bt5)), bt6, bt7
        return protocol_type

    def json_construct(self, config):
        """构建为json格式"""
        return {
            'total_length': self.total_length,
            'command_id': self.command_id,
            'sequence_id': self.sequence_id,
            'msg_id': self.msg_id,
            'pk_total': self.pk_total,
            'pk_number': self.pk_number,
            'registered_delivery': self.registered_delivery,
            'msg_level': self.msg_level,
            'service_id': self.service_id,
            'fee_user_type': self.fee_user_type,
            'fee_terminal_id': self.fee_terminal_id,
            'tp_pid': self.tp_pid,
            'tp_udhi': self.tp_udhi,
            'msg_fmt': self.msg_fmt,
            'msg_src': self.msg_src,
            'fee_type': self.fee_type,
            'fee_code': self.fee_code,
            'valid_time': self.valid_time,
            'at_time': self.at_time,
            'src_id': self.src_id[len(config['virtual_code']):],
            'destusr_tl': self.destusr_tl,
            'dest_terminal_id': self.dest_terminal_id,
            'msg_length': self.msg_length,
            'msg_content': self.msg_content,
            'reserve': self.reserve,
            'xx': self.xx,
            'mm': self.mm,
            'nn': self.nn,
        }
