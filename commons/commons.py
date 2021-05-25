def sequence_id_gen(sequence_id):
    """sequence id 计算方法"""

    if sequence_id <= 2 ** 31:
        sequence_id += 1
        return sequence_id
    else:
        return 0
