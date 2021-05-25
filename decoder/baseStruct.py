import struct


def pack_4_unsigned_integer(data):
    return struct.pack('!I', data)


def unpack_4_unsigned_integer(data):
    return struct.unpack('!I', data)


def pack_1_unsigned_integer(data):
    return struct.pack('!B', data)


def unpack_1_unsigned_integer(data):
    return struct.unpack('!B', data)


def pack_8_unsigned_integer(data):
    return struct.pack('!Q', data)


def unpack_8_unsigned_integer(data):
    return struct.unpack('!Q', data)


def data_resolution(data, residue=b''):
    """拆包"""
    msg_pool = []
    try:
        while len(data) > 0:
            # 如果是第一次循环并且residue不为空
            if residue is not None:
                data = residue + data
                residue = None
            total_length = unpack_4_unsigned_integer(data[0: 4])[0]
            if len(data) >= total_length:
                msg_pool.append(data[0: total_length])
                data = data[total_length:]
            else:
                residue = data
                break
    except struct.error as e:
        residue = data
    # ([b"\x00\x00\x00'\x00\x00\x00\x01\x02\xeb\x0e\xa4liyi12{Cj\xc5?\xd2z\xa1\xfd\x03\xdf\rzJ\x0ff \x19H\x15/"], None)
    return msg_pool, residue


def _message_header_parser(msg=b''):
    """
    信息头解析
    :param msg:
    :return:
    """
    _total_length = unpack_4_unsigned_integer(msg[0: 4])[0]
    _command_id = unpack_4_unsigned_integer(msg[4: 8])[0]
    _sequence_id = unpack_4_unsigned_integer(msg[8: 12])[0]

    return _total_length, _command_id, _sequence_id