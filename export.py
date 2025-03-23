import sqlite3
import sns_pb2
from io import BytesIO
import argparse
import json 

class User:
    def __init__(self, name, wxid):
        self.name = name
        self.wxid = wxid
    def to_json(self):
        return { 
            "name": self.name, 
            "wxid": self.wxid 
        }
class Msg:
    def __init__(self, local_id, pb_msg):
        self.local_id = local_id
        self.id = pb_msg.id
        self.create_time = pb_msg.create_time
        self.content = pb_msg.content
        self.author_wxid = pb_msg.author_wxid
        self.author_name = pb_msg.author_name
        self.favorite_count = pb_msg.favorite_count
        self.favorite_users = Msg.parse_favorite_users(pb_msg.favorite_detail)
        self.comment_count = pb_msg.comment_count
        self.comment_detail = pb_msg.comment_detail
    def to_json(self):
        return { 
            "local_id": self.local_id, 
            "id": self.id,
            "create_time": self.create_time,
            "content": self.content,
            "author_wxid": self.author_wxid,
            "author_name": self.author_name,
            "favorite_count": self.favorite_count,
            "favorite_users": list(map(lambda i: i.to_json(), self.favorite_users)),
            "comment_count": self.comment_count,
            "comment_detail": self.comment_detail.hex(),
        }
    def parse_favorite_users(favorite_detail):
        buffer = BytesIO(favorite_detail)
        users = []
        while True:
            header = buffer.read(9)
            if len(header) != 9:
                break
            t = buffer.read(1)[0]
            assert t == 0x22
            l = buffer.read(1)[0]
            name = buffer.read(l).decode('utf-8')

            t = buffer.read(1)[0]
            assert t == 0x1a
            l = buffer.read(1)[0]
            wxid = buffer.read(l).decode('utf-8')
            users.append(User(name, wxid))
            buffer.read(14)
        return users

def get_sns_data(db, user_id):
    con = sqlite3.connect(db)
    cur = con.cursor()
    res = cur.execute("SELECT Buffer, LocalId, Id, FromUser FROM SNS_Timeline where FromUser=?", (user_id,))
    items = res.fetchall()
    return items

def parse_pb_content(buffer):
    msg = sns_pb2.SnsTimeline()
    msg.ParseFromString(buffer)
    return msg

def export_sns(db, user):
    print('Exporting data of user=%s in %s' %(user, db))
    items = get_sns_data(db, user)
    print('%s item found' % len(items))
    messages = []
    for item in items:
        pb_msg = parse_pb_content(item[0])
        record = Msg(item[1], pb_msg)
        messages.append(record)
    messages.sort(reverse=True, key=lambda x: x.create_time)
    return messages

if __name__ == '__main__':
    parser = argparse.ArgumentParser("SNS exporter")
    parser.add_argument("sns_cache", help="SNS cache db file(without cipher)", type=str)
    parser.add_argument("wxid", help="The from user , aka. SNS_Timeline.FromUser", type=str)
    args = parser.parse_args()
    messages = export_sns(args.sns_cache, args.wxid)
    print("Successfully parsed %d messages" % len(messages))
    arr = list(map(lambda i: i.to_json(), messages))
    json = json.dumps(arr, ensure_ascii=False)
    print(json)