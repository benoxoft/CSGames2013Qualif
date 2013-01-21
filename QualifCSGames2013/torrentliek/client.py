#! /usr/bin/env python
# -*- coding: utf8 -*- 

# Par Benoit Paquet - 2013-01-18
# Client bittorrent like pour les qualifications des CSGames 2013

import hashlib
import math
import os
import socket
import sys
import threading
import uuid

TRACKER_ADDRESS = ('localhost', 12345)
DEFAULT_PEER_IP = 'localhost'
DEFAULT_PEER_PORT = 11234
CHUNK_SIZE = 1000000.0

def port_shuffler():
    """Générateur de ports.  Permet aux clients de se connecter sur 
        différents ports."""
    while True:
        for i in xrange(22100, 22200):
            yield i
port_gen = port_shuffler()
def next_port():
    return port_gen.next()

def connect_to_tracker():
    """Créé et retourne un socket connecté au tracker"""
    sock = socket.socket()
    sock.connect(TRACKER_ADDRESS)
    return sock

def connect_to_peer(ip, port=DEFAULT_PEER_PORT):
    """Établi une connection avec un pair"""
    
    sock = socket.socket()
    try:
        sock.connect((ip, port))
        return sock
    except Exception, e:
        print e
        return None

def send_message_to_tracker(action, *data):
    """Envoi un message au tracker
        action: L'action à exécuter sur le tracker.  Par exemple obtenir
            la liste des clients qui possèdent un fichier
        data: Les données à envoyer au tracker.  
            Par exemple le checksum du ficher
        
        Retourne la réponse du tracker"""
        
    sock = connect_to_tracker()
    message = action + ' ' + ' '.join(data) + '\n'
    sock.send(message)
    eof = False
    ret = ''
    while not eof:
        s = sock.recv(1024)
        ret += s
        eof = ret[-1] == '\n'
    sock.close()
    return ret
    
def send_message_to_peer(sock, action, *data):
    """Envoi un message à un pair.
        Reçoit un socket déjà connecté au pair.
        
        Retourne la réponse du pair"""
        
    message = action + ' ' + ' '.join([str(s) for s in data]) + '\n'
    sock.send(message)
    eof = False
    ret = ''
    while not eof:
        s = sock.recv(1024)
        ret += s
        eof = ret[-1] == '\n'
    sock.close()
    return ret

def match_file(checksum):
    """Reçoit un checksum en paramètre.  Trouve le fichier correspondant
        dans le répertoire 'torrents'."""
        
    if not os.path.exists('torrents'):
        os.mkdir('torrents')
    for f in os.listdir('torrents'):
        if os.path.isfile(os.path.join('torrents', f)):
            cs = action_checksum(f)
            if cs == checksum:
                return f

def calc_chunk_amount(file_size):
    """Calcule la quantité de blocs dans le fichier à télécharger."""
    
    return math.ceil(file_size / CHUNK_SIZE)

def download_file(file_name, ip, next_chunk, file_size):
    """Se connecte à un pair et télécharge les blocs de fichiers disponibles."""
    
    sock = client_reconnect(ip, file_name)
    downloaded = 0
    chunk_size = int(CHUNK_SIZE)
    for chunk in next_chunk:
        print '/r/ing chunk ' + str(chunk) + ' from ' + ip[:-1]
        if file_size - downloaded < chunk_size:
            chunk_size = file_size - downloaded
        downloaded += chunk_size 
        data = client_get_chunk(sock, chunk, chunk_size)
        write_to_file(file_name, data, chunk)
    sock.close()
    
def upload_file(file_name, sock):
    """Envoi un fichier à un pair"""
    
    conn, addr = sock.accept()
    connected = True
    msg = ''
    while connected:
        data = conn.recv(32)
        if data == '':
            connected = False
            continue
        
        action, chunk = data[0:-1].split(' ')
        print 'Sending chunk ' + chunk + ' to ' + addr[0]
        chunk = int(chunk)
        conn.send(server_get_chunk(file_name, chunk))
    print 'End of transfer for file ', file_name
    conn.close()

file_lock = threading.Lock()
def write_to_file(file_name, data, chunk):
    """Écrit un bloc téléchargé dans le fichier de destination"""
    
    file_lock.acquire()
    if not os.path.exists('torrents'):
        os.mkdir('torrents')
        
    try:
        f = open(os.path.join('torrents', file_name), 'r+b')
        f.seek(int(chunk * CHUNK_SIZE))
        f.write(data)
        f.close()
    finally:
        file_lock.release()
        
def run_server(uid, checksums):
    """Serveur de fichiers pour les pairs"""
    
    sock = socket.socket()
    sock.bind((DEFAULT_PEER_IP, DEFAULT_PEER_PORT))
            
    while True:
        sock.listen(10)
        try:
            print 'Waiting for a connection from a peer...'
            conn, addr = sock.accept()
            ip = addr[0]
            print 'Connected to: ', ip
            t = threading.Thread(target=handle_connection, args=(conn, ip))
            t.start()
        except Exception, e:
            print e
            pass           

def handle_connection(conn, ip):
    """Gère la connexion d'un pair sur le port par défaut"""
    
    connected = True
    msg = ''
    while connected:
        s = conn.recv(1024)
        msg += s
        if msg[-1] == '\n':
            data = msg[0:-1].strip().split(' ')
            method = '_'.join(('server', data[0]))
            if hasattr(main, method):
                retval = str(getattr(main, method)(*data[1:])) + '\n'
                conn.send(retval)
                connected = False
    conn.close()

def action_keygen():
    """Génère un identifiant unique pour le client.
    
        Syntaxe: client keygen"""

    print str(uuid.uuid4())
    
def action_checksum(file):
    """Génère le md5sum du fichier spécifié.
        Le fichier doit exister dans le répertoire 'torrents'.
    
        Syntaxe: client checksum <nomfichier>"""

    f = open(os.path.join('torrents', file))
    sum = hashlib.md5()
    eof = False
    while not eof:
        s = f.read(128)
        sum.update(s)
        eof = len(s) != 128
    print sum.hexdigest()
    return sum.hexdigest()
    
def action_submit(client_uid, checksum):
    """Soumet le checksum d'un fichier au tracker pour indiquer que celui-ci
        est disponible à l'adresse de ce client.
        
        Syntaxe: client submit <uid> <checksum>"""
    print send_message_to_tracker('submit', client_uid, checksum)
        
def action_find_client(checksum):
    """Retourne une liste de tous les clients qui possèdent le fichier
        correspondant au checksum
        
        Syntaxe: client find-client <checksum>"""
        
    print '/r/ing sauce for ' + checksum
    ret = send_message_to_tracker('find_client', checksum)
    if ret == '\n':
        return {}
    
    clients = {s.split('->')[0] : s.split('->')[1] 
               for s in [s for s in ret.split('|')]}
    print '\n'.join([' '.join((ip, uid)) for ip, uid in clients.items()])
    print 'Thank you based tracker.'
    return clients
        
def action_get(checksum):
    """Télécharge un fichier
    
        Syntaxe: client get <checksum>"""
        
    clients = action_find_client(checksum)
    clients = client_verify(clients)
    
    print 'Clients verified'
    
    if len(clients) == 0:
        print 'No seeders!'
        return
    
    file_name = client_file_name(clients, checksum)
    open(os.path.join('torrents', file_name), 'w').close()
    
    print 'Name of file: ', file_name
    file_size = client_file_size(clients, file_name)
    chunks = calc_chunk_amount(file_size)
    def chunk_counter(chunks):
        def next_chunk():
            for i in xrange(0, int(chunks)):
                yield i
        return next_chunk()
    next_chunk = chunk_counter(chunks)
    
    threads = []
    for _, ip in clients.items():
        t = threading.Thread(target=download_file, 
                             args=(file_name, ip, next_chunk, file_size))
        threads.append(t)
        t.start()
    for t in threads:
        t.join()
    assert checksum == action_checksum(file_name)
    print 'Got file.  Thank you based internet.'
    
def action_serve(client_uid, *checksums):
    """Indique au tracker les fichiers que le client partage
    
        Syntaxe: client serve <uid> <checksum1> <cs2> <cs3>... """
        
    for cs in checksums:
        action_submit(client_uid, cs)
    run_server(client_uid, checksums)
    
def client_reconnect(ip, file_name):
    """Permet à un client et un serveur de se connecter sur un nouveau port
        L'objectif est de libérer le port par défaut"""
    
    sock = connect_to_peer(ip)
    new_port = send_message_to_peer(sock, 'reconnect', file_name)
    sock.close()
    sock = connect_to_peer(ip, int(new_port))
    return sock

def server_reconnect(file_name):
    """Obtient un nouveau # de port et le retourne au client."""
    
    while True:
        try:
            port =  next_port()
            sock = socket.socket()
            sock.bind((DEFAULT_PEER_IP, port))
            sock.listen(1)
            t = threading.Thread(target=upload_file, args=(file_name, sock))
            t.start()
            return port
        except Exception, e:
            print e
    
    
def client_get_chunk(sock, chunk, chunk_size):
    """Va chercher un bloc du fichier chez un pair"""
    
    message = 'get_chunk ' + str(chunk) + '\n'
    sock.send(message)
    ret = ''
    while not len(ret) == int(chunk_size):
        s = sock.recv(int(chunk_size))
        ret += s
    return ret
    
def server_get_chunk(file_name, chunk):
    """Envoi un bloc de données au client"""
    
    f = open(os.path.join('torrents', file_name))
    f.seek(int(chunk) * int(CHUNK_SIZE))
    data = f.read(int(CHUNK_SIZE))
    f.close()
    return data

def client_verify(clients):
    """Vérifie que les pairs sont toujours actifs"""
    
    valid_clients = {}
    for uid, ip in clients.items():
        try:
            print 'Trying ', ip
            sock = connect_to_peer(ip)
            assert send_message_to_peer(sock, 'verify') == 'verified\n'
            valid_clients[uid] = ip
        except:
            pass

    return valid_clients

def server_verify():
    return 'verified'

def client_file_size(clients, file_name):
    """Va chercher la taille du fichier à télécharger"""
    
    for uid, ip in clients.items():
        sock = connect_to_peer(ip)
        return int(send_message_to_peer(sock, 'file_size', file_name))

def server_file_size(file_name):
    """Retourne la taille d'un fichier"""
    
    f = os.path.join('torrents', file_name)
    if os.path.exists(f):
        return os.path.getsize(f)
    else:
        return 0

def client_file_name(clients, checksum):
    """Va chercher le nom du fichier selon son checksum"""
    
    for uid, ip in clients.items():
        sock = connect_to_peer(ip)
        return send_message_to_peer(sock, 'file_name', checksum)[0:-1]

def server_file_name(checksum):
    """Retourne le nom du fichier selon le checksum"""
    print 'Searching for ', checksum
    file_name = match_file(checksum)
    return file_name


if __name__ == '__main__':
    main = sys.modules[__name__]
    
    for i in xrange(0, len(sys.argv)):
        arg = sys.argv[i]
        if arg[0:10] == 'trackerip=':
            TRACKER_ADDRESS = (arg[10:], 12345)
            continue
        elif arg[0:9] == 'serverip=':
            DEFAULT_PEER_IP = arg[9:]
            continue
        method = 'action_' + sys.argv[i].replace('-', '_')
        if hasattr(main, method):
            if i + 1 == len(sys.argv):
                getattr(main, method)()
                sys.exit(0)
            else:
                getattr(main, method)(*sys.argv[i+1:])
                sys.exit(0)
    print 'Invalid argument.'
    