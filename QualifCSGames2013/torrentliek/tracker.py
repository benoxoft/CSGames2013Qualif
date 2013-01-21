#! /usr/bin/env python
# -*- coding: utf8 -*- 

# Par Benoit Paquet - 2013-01-18
# Tracket bittorrent like pour les qualifications des CSGames 2013


import socket
import sys
import time
from threading import Thread

main = sys.modules[__name__]

TRACKER_PORT = 12345

#clé: uid, value: ip
clients = {}

#clé: checksum, value(uid1, uid2...)
files = {}

def tracker_submit(ip, uid, checksum):
    print ' '.join((ip, 'submitted', uid, 'and', checksum))
    if not clients.has_key(uid):
        clients[uid] = ip
    else:
        print 'uid already exists!'
    if not files.has_key(checksum):
        files[checksum] = []
    if not uid in files[checksum]:
        files[checksum].append(uid)
    else:
        print 'uid already identified with file!'
    return 'Thank you based client.'

def tracker_find_client(ip, checksum):
    print 'Finding clients for ' + checksum 
    if files.has_key(checksum):
        return '|'.join(('->'.join((uid, ip)) 
                    for uid, ip in clients.items() if uid in files[checksum]))
    else:
        return ''

def handle_connection(conn, ip):
    connected = True
    msg = ''
    while connected:
        s = conn.recv(1024)
        msg += s
        if msg[-1] == '\n':
            data = msg.split(' ')
            method = '_'.join(('tracker', data[0]))
            if hasattr(main, method):
                retval = getattr(main, method)(ip, *data[1:]) + '\n'
                print retval
                conn.send(retval)
                connected = False
    conn.close()
    
def listen_until_forever(listenip):
        sock = socket.socket()
        sock.bind((listenip, TRACKER_PORT))
                
        while True:
            sock.listen(10)
            try:
                print 'Waiting for a connection...'
                conn, addr = sock.accept()
                ip = addr[0]
                print 'Connected to: ', ip
                t = Thread(target=handle_connection, args=(conn, ip))
                t.start()
            except Exception, e:
                print e
                pass           

if __name__ == '__main__':
    if len(sys.argv) > 2:
        print "Trop d'arguments..."
        sys.exit(0)
    elif len(sys.argv) == 2:
        listen_until_forever(sys.argv[1])
    else:
        listen_until_forever('localhost')
        