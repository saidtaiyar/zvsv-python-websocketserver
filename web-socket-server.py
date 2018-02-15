#!/usr/bin/python
# -*- coding: utf-8 -*-

import struct #из него нам нужна функция pack() и unpack_from()
import array # функция array()
import pymysql as DB #Для работы с БД MySQL
import json #для работы с JSON
import socket # Сами сокеты
import threading #По потоку для каждого подключения
from hashlib import sha1 #Кодирование Access Key 
from base64 import b64encode #Кодирование Access Key

class webSocketServer:

    #Словарь (ассоциативный массив) соединений
    connections = {}
    db_host = "mysql-server"
    db_user = "user"
    db_pass = "pass"
    db_base = "somedb"

    server_sess_id = 'sdf5886rdg8gfj557v9hlkdsdf7rhbsd' #ИД для сокета (main), сервера

    def __init__(self):
        self.start_server()
        
    ##########################################################
    '''Выполнить SQL'''
    ##########################################################
    def sqlExecute(self, sql):
        try:
            print(sql)
            con = DB.connect(host=self.db_host, user=self.db_user, passwd=self.db_pass, db=self.db_base, charset='utf8')
            cur = con.cursor()
            cur.execute(sql)

            return {'cur':cur,'con':con}      
        except DB.Error:
            dbe = 1

    ##########################################################
    '''Получаем id пользователя по sess_id'''
    ##########################################################
    def getUserIdBySessId(self, sess_id):

        #Экранируем одинарную ковычку
        sess_id = sess_id.replace("'", "\\'")

        # Это значит что сообщение от сервера
        if sess_id == self.server_sess_id:
            return 0
        else:
            sql = ("SELECT id FROM tts77_users WHERE sess_id = '%s'") % (sess_id)
            resultSqlExecute = self.sqlExecute(sql)
            result = resultSqlExecute['cur'].fetchall()
            resultSqlExecute['con'].close()
        
            for row in result:
                return row[0]

    ##########################################################
    '''Отправка сообщения пользователю'''
    ##########################################################
    def pushMsgToUser(self, user_id, data, msg_type):
        error = False
        #Обращаемся к соединению интересующего нас пользователя
        if 'to_id' in data:
            to_id = int(data['to_id']) #Перевод строки в число
            if to_id in self.connections:
                con = self.connections[to_id]['con']
            else:
                con = self.connections[user_id]['con']
                error = {'id': 701, 'msg': 'user_ofline'}
        else: 
            return False

        #Проверяем на integer
        if type(user_id) != int or type(to_id) != int:
            return False

        if 'msg' in data:
            #Экранируем одинарную ковычку
            data['msg'] = data['msg'].replace("'", "\\'")
        else:
            return False;

        if msg_type != 'new_alerts':
            #Пишем сообщение в базу
            sql = ("INSERT INTO tts77_users_messages (`type`, `to_id`, `from_id`, `content`, `date`) VALUES ('%s', '%s', '%s', '%s', NOW())") % (msg_type, to_id, user_id, data['msg'])
            result = self.sqlExecute(sql)
            result['con'].commit()
            result['con'].close()
        
        #Проверяем на наличие ошибок
        if(error):
            arr_data = {'type': msg_type, 'error': error}
        else:
            arr_data = {'type': msg_type, 'data': {'user_id': user_id, 'msg': data['msg']}}

        #Собираем объект и отправляем в JSON
        jmsg = json.dumps(arr_data, separators=(',',':'))
        con.send(self.pack_frame(jmsg.encode('utf-8'),0x1))

    ##########################################################
    '''Распаковка'''
    ##########################################################
    def unpack_frame(self, data):
        frame = {}
        if data == b'':
            frame['length'] = 0
            return frame
        byte1, byte2 = struct.unpack_from('!BB', data)
        frame['fin'] = (byte1 >> 7) & 1
        frame['opcode'] = byte1 & 0xf
        masked = (byte2 >> 7) & 1
        frame['masked'] = masked
        mask_offset = 4 if masked else 0
        payload_hint = byte2 & 0x7f
        if payload_hint < 126:
            payload_offset = 2
            payload_length = payload_hint               
        elif payload_hint == 126:
            payload_offset = 4
            payload_length = struct.unpack_from('!H',data,2)[0]
        elif payload_hint == 127:
            payload_offset = 8
            payload_length = struct.unpack_from('!Q',data,2)[0]
        frame['length'] = payload_length
        payload = array.array('B')
        payload.fromstring(data[payload_offset + mask_offset:])
        if masked:
            mask_bytes = struct.unpack_from('!BBBB',data,payload_offset)
            for i in range(len(payload)):
                payload[i] ^= mask_bytes[i % 4]
        frame['payload'] = payload.tostring()
        return frame

    ##########################################################
    '''Упаковка'''
    ##########################################################
    def pack_frame(self, buf, opcode, base64=False):
             
        if base64:
            buf = b64encode(buf)
             
        b1 = 0x80 | (opcode & 0x0f) # FIN + opcode
        payload_len = len(buf)
        if payload_len <= 125:
            header = struct.pack('>BB', b1, payload_len)
        elif payload_len > 125 and payload_len < 65536:
            header = struct.pack('>BBH', b1, 126, payload_len)
        elif payload_len >= 65536:
            header = struct.pack('>BBQ', b1, 127, payload_len)
             
        return header+buf


    ##########################################################
    '''Создаем заголовок для рукопажатия, нового соединения'''
    ##########################################################
    def create_handshake(self, handshake):
         result = {}
         lines = handshake.splitlines() # Делим построчно
         for line in lines: #Итерируемся по строкам
            parts = line.decode('utf-8').partition(': ') # Делим по ':'
            #Собираем заголовок
            if parts[0] == 'Sec-WebSocket-Key':
                key = parts[2] # Находим необходимый ключ
                key += '258EAFA5-E914-47DA-95CA-C5AB0DC85B11' 
                Acckey=b64encode((sha1(key.encode('utf-8'))).digest())
                result['header'] = ((
                    'HTTP/1.1 101 Switching Protocols\r\n'
                    'Upgrade: websocket\r\n'
                    'Connection: Upgrade\r\n'
                    'Sec-WebSocket-Accept: %s\r\n'
                    '\r\n'
                    ) % (Acckey.decode('utf-8')))
            #Вытягиваем id сессии
            if parts[0] == 'Cookie':
                cooke = parts[2].split('; ')
                for val_1 in cooke:
                    val_2 = val_1.partition('=')
                    if val_2[0] == 'PHPSESSID':
                        result['sess_id'] = val_2[2]
         return result
                
    ##############################################
    '''Делаем рукопажатие для нового соединения'''
    ##############################################    
    def handle(self, s, addr):
        data = s.recv(1024)
        ch_result = self.create_handshake(data)
        #Отправляем клиенту заголовок для рукопожатия
        s.send(ch_result['header'].encode('utf-8'))
        sess_id = ch_result['sess_id']
        #Достаем id пользователя по его сессии
        user_id = self.getUserIdBySessId(sess_id)
        
        self.connections[user_id] = {'con': s, 'sess_id': sess_id, 'addr': addr};
        
        while True:
            data = s.recv(1024)
            unpacked_data = self.unpack_frame(data)
            if unpacked_data['length'] <= 2: #Если размер данных <= 2 (при закрытии соединения приходят данные размером 2, непонятно что это)
                #Нет данных от клиента, удаляем его из словаря соединений
                del self.connections[user_id]
                break
            jmsg = json.loads( unpacked_data['payload'].decode('utf-8') )
            self.pushMsgToUser(user_id, jmsg['data'], jmsg['type'])
            
    #####################
    '''СТАРТУЕМ СЕРВЕР'''
    #####################
    def start_server(self):
        s = socket.socket()
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(('', 9090))
        s.listen(1)
        while 1:
            conn, addr = s.accept()
            threading.Thread(target = self.handle, args = (conn, addr)).start()

#Создаем объект             
wss = webSocketServer()
