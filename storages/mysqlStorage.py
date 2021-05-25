import pymysql


class Base:
    """基本链接"""
    def __init__(self, host, user, password, database):
        self.host = host
        self.user = user
        self.password = password
        self.database = database
        self.db = pymysql.connect(host=host, user=user, password=password, database=database)
        self.cursor = self.db.cursor()

    def select_one(self, sql):
        """查找单个数据"""
        self.cursor.execute(sql)
        res = self.cursor.fetchone()
        return res[0] if res is not None else None

    def close(self):
        """关闭链接"""
        self.cursor.close()
        self.db.close()
