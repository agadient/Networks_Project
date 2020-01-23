import os
import SocketServer
import socket
from socket import *
from struct import pack, unpack
from scapy.all import *
import nfqueue
import Crypto
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
from Crypto import Random
from Crypto.Signature import PKCS1_v1_5
from Crypto.Hash import SHA256
from threading import Thread
from time import sleep
from hashlib import md5
import asyncore
import re
ipv4_pattern = re.compile("^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$")
home_path = os.path.expanduser("~")
#Generate my RSA key
def generate_private_key():
    try:
        RSA_priv_key_txt = open("{}/.bitcoin/rsa.key".format(home_path))
        RSA_priv_key_txt = RSA_priv_key_txt.read()
        RSA_priv_key = RSA.importKey(RSA_priv_key_txt)
        return RSA_priv_key
    except IOError:
        print("No RSA private key file found, generating a new one")
        f = open("{}/.bitcoin/rsa.key".format(home_path), 'w')
        random_generator = Random.new().read
        RSA_priv_key = RSA.generate(1024, random_generator)
        f.write(RSA_priv_key.exportKey(format = "PEM", passphrase=None, pkcs=1))
        return RSA_priv_key

my_RSA_priv_key = generate_private_key()
#Generate one_time_pad
One_time_pads = {}
One_time_pads["my_key"] = os.urandom(4096)
# Get my ip address
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.connect(("8.8.8.8", 80))
my_ip = s.getsockname()[0]
ip_addresses = []


# Read configuration file for peers
def set_iptables():
    
    bitcoin_conf = open("{}/.bitcoin/bitcoin.conf".format(home_path))
    bitcoin_conf = bitcoin_conf.read()
    bitcoin_conf = bitcoin_conf.splitlines()
    for line in bitcoin_conf:
        if (len(line) > 0 and line[0] != '#'):
            line = line.split('=')
            if(line[0] == "connect"):
                ip_addresses.append(line[1])
    os.system("sudo iptables -F")
    for addr in ip_addresses:
        os.system("sudo iptables -A OUTPUT -s {} -d {} -p tcp --dport 8333 -j NFQUEUE --queue-num 1".format(my_ip, addr))
        os.system("sudo iptables -A INPUT -d {} -s {} -p tcp --sport 8333 -j NFQUEUE --queue-num 2".format(my_ip, addr))
            
# Encrypt AES data
def AES_encrypt(secret_key, data):
    iv = Random.new().read(AES.block_size)
    aes = AES.new(secret_key, AES.MODE_CFB, iv)
    return (iv + aes.encrypt(data))

# Decrypt AES data
def AES_decrypt(secret_key, data):
    iv = data[0:16]
    aes = AES.new(secret_key, AES.MODE_CFB, iv)
    return aes.decrypt(data[16::])

# Connect to peers in conf file and exchange keys with them if they support encryption
def exchange_OTP_keys(peer):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # Timeout value would probably need to be changed for real application. Would be worth pinging first to get RTT to peer
    s.settimeout(1.0)
    try:
        s.connect((peer, 7000))
        s.send("OTP")
        response = s.recv(3)
        if response != "OTP":
            print("Peer {} does not support OTP encryption".format(peer))
            return False
        
        else:            
            AES_secret = my_RSA_priv_key.decrypt(s.recv(128))
            one_time_pad_enc = s.recv(8192)
            session_one_time_pad = AES_decrypt(AES_secret, one_time_pad_enc)
            s.send(AES_encrypt(AES_secret, One_time_pads["my_key"]))
            return session_one_time_pad
    except Exception as e:
        print("Problem while exchanging keys {}".format(e))
        return False
def get_trusted_peers():
    trusted_peers_txt = open("{}/.bitcoin/trusted.keys".format(home_path))
    trusted_peers_txt = trusted_peers_txt.read()
    trusted_peers_txt = trusted_peers_txt.splitlines()
    peers_list = []
    for line in trusted_peers_txt:
        if ipv4_pattern.match(line):
            peers_list.append(line)
    return peers_list

def get_trusted_peer_pub_key(trusted_peer):
    trusted_peers_txt = open("{}/.bitcoin/trusted.keys".format(home_path))
    trusted_peers_txt = trusted_peers_txt.read()
    trusted_peers_txt = trusted_peers_txt.splitlines()
    peers_list = []
    starti = 0
    endi = 0
    i = 0 
    start = False
    for line in trusted_peers_txt:
        if start != False and line.find("END") != -1:
            endi = i + 1
        if line == trusted_peer:
            starti = i+1
            start = True
        i += 1
    peer_pub_key = ''.join((elem + '\n') for elem in trusted_peers_txt[starti:endi])

    return peer_pub_key[0:-1]


def add_public_key(peer_pub_key, ip_address):
    trusted_peers_txt = open("{}/.bitcoin/trusted.keys".format(home_path), "a+")
    trusted_peers_txt.write(ip_address + "\n" + peer_pub_key + "\n")

def exchange_RSA_pub_keys(ip_address, my_pub_key):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((ip_address, 7000))
    s.settimeout(3.0)
    s.send("RSA")
    if (s.recv(10) != "Who trust?"):
        print("{} does not support RSA encryption".format(ip_address))
    else:
        trusted_peers = ""
        for peer in get_trusted_peers():
            trusted_peers += peer + "\n"
        s.send(trusted_peers)
        peer_pub_key = s.recv(2048)
        num_sigs = int(peer_pub_key[-1])
        peer_pub_key = peer_pub_key[0:-1]
        for i in range(num_sigs):
            trusted_peer = s.recv(1024)
            trusted_peer_pub_key = RSA.importKey(get_trusted_peer_pub_key(trusted_peer), passphrase=None)
            signature = s.recv(1024)
            h = SHA256.new(peer_pub_key)
            if PKCS1_v1_5.new(trusted_peer_pub_key).verify(h, signature):
                add_public_key(peer_pub_key, ip_address)
        s.send("Who trust?")
        trusted = s.recv(1024)
        trusted = trusted.splitlines()
        signatures = {}
        for trusted_peer in trusted:
            sig_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sig_sock.connect((trusted_peer, 7000))
            sig_sock.send("SIG")
            if (sig_sock.recv(3) == "SIG"):
                sig_sock.send(my_pub_key)
                signature = sig_sock.recv(1024)
                signatures[trusted_peer] = signature
                sig_sock.close()
            else:
                print("Cannot get get signature from trusted peer")
            s.send(my_pub_key + str(len(signatures)))
            for (trusted_peer, signature) in signatures.iteritems():
                s.send(trusted_peer)
                sleep(0.1)
                s.send(signature)
                sleep(0.1)
            return True
            
    return False

def verify_key(peer, public_key):
    
    trusted_peers_txt = open("{}/.bitcoin/trusted.keys".format(home_path))
    trusted_peers_txt = trusted_peers_txt.read()
    trusted_peers_txt = trusted_peers_txt.splitlines()
    start = False
    starti = 0
    endi = 0
    for line in trusted_peers_txt:  
            starti = trusted_peers_txt.index(peer)+1
            break
    public_key = public_key.splitlines()
    i = 0
    for line in public_key:
        if line != trusted_peers_txt[starti+i]:
            return False
        i += 1
    else:
        return True
def setup_RSA_OTP_SIG_server(my_pub_key):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind((my_ip, 7000))
    s.listen(1)
    try:
        while True:
            connection, client_address = s.accept()
            message = connection.recv(3)
            if(message == "RSA"):
                connection.send("Who trust?")
                trusted = connection.recv(1024)
                trusted = trusted.splitlines()
                signatures = {}
                for trusted_peer in trusted:
                    sig_sock = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
                    sig_sock.connect((trusted_peer, 7000))
                    sig_sock.send("SIG")
                    if(sig_sock.recv(3) == "SIG"):
                        sig_sock.send(my_pub_key)
                        signature = sig_sock.recv(1024)
                        signatures[trusted_peer] = signature
                        sig_sock.close()
                    else:
                        print("Cannot get signature from trusted peer")
                connection.send(my_pub_key + str(len(signatures)))
                sleep(0.1)
                for (trusted_peer, signature) in signatures.iteritems():
                    connection.send(trusted_peer)
                    sleep(0.1)
                    connection.send(signature)
                    sleep(0.1)
                if(connection.recv(10) == "Who trust?"):
                    trusted_peers = ""
                    for peer in get_trusted_peers():
                        trusted_peers += peer + "\n"
                    connection.send(trusted_peers)
                    peer_pub_key = connection.recv(2048)
                    num_sigs = int(peer_pub_key[-1])
                    peer_pub_key = peer_pub_key[0:-1]
                    for i in range(num_sigs):
                        trusted_peer = connection.recv(1024)
                        trusted_peer_pub_key = RSA.importKey(get_trusted_peer_pub_key(trusted_peer), passphrase = None)
                        signature = connection.recv(1024)
                        h = SHA256.new(peer_pub_key)
                        if PKCS1_v1_5.new(trusted_peer_pub_key).verify(h, signature):
                            add_public_key(peer_pub_key, client_address[0])
                                 
        
            elif (message == "OTP"):
                connection.send("OTP")
                peer_public_key = RSA.importKey(get_trusted_peer_pub_key(client_address[0]), passphrase=None)
                AES_secret = os.urandom(16)
                connection.send(peer_public_key.encrypt(AES_secret, 32)[0])
                one_time_pad_enc = AES_encrypt(AES_secret, One_time_pads["my_key"])
                connection.send(one_time_pad_enc)
                peer_one_time_pad = AES_decrypt(AES_secret, connection.recv(8192))
                One_time_pads[client_address[0]] = peer_one_time_pad
                os.system("sudo iptables -A INPUT -s {} -d {}  -p tcp --dport 8333 -j NFQUEUE --queue-num 2".format(client_address[0], my_ip))
                os.system("sudo iptables -A OUTPUT -s {} -d {}  -p tcp --sport 8333 -j NFQUEUE --queue-num 1".format(my_ip, client_address[0]))
            elif (message == "SIG"):
                connection.send("SIG")
                public_key = connection.recv(1024)
                if verify_key(client_address[0], public_key) == True:
                    signer = PKCS1_v1_5.new(my_RSA_priv_key)
                    h = SHA256.new(public_key)
                    signature = signer.sign(h)
                    connection.send(signature)
    
        connection.close()
    except KeyboardInterrupt:
        s.close()
def have_RSA_pub_key(ip_addr):
    trusted_peers_txt = open("{}/.bitcoin/trusted.keys".format(home_path))
    trusted_peers_txt = trusted_peers_txt.read().splitlines()
    for line in trusted_peers_txt:
        if (line == ip_addr):
            return True
    return False

# Setup the RSA keys for nodes in the configuration file
def setup_RSA():
    for ip_address in ip_addresses:
        if have_RSA_pub_key(ip_address) == False:
            if exchange_RSA_pub_keys(ip_address, my_RSA_priv_key.publickey().exportKey()) == True:
                One_time_pads[ip_address] = exchange_OTP_keys(ip_address)
            else:
                print("Unable to set up RSA pub keys with {}".format(ip_address))
        else:
            One_time_pads[ip_address] = exchange_OTP_keys(ip_address)
    print("Keys setup. The md5 hashes for the keys are:")
    for ip_addr, key in One_time_pads.iteritems():
        m = md5()
        m.update(key)
        print("{} : {}".format(ip_addr, m.hexdigest()))

# Decrypt packets in the queue
def decrypt_pkt(num, pkt):
    data = pkt.get_data()
    scapy_pkt = IP(data)
    old_payload = str(scapy_pkt[TCP].payload)
    if len(old_payload) > 0:
        my_pad = One_time_pads["my_key"][0:len(old_payload)]
        new_payload = ''.join(chr(ord(p) ^ ord(c)) for p,c in zip(old_payload, my_pad))        
        scapy_pkt[TCP].remove_payload()
        scapy_pkt[TCP].add_payload(new_payload)
        del scapy_pkt[IP].chksum
        del scapy_pkt[TCP].chksum
        scapy_pkt.show2(dump=True)
        pkt.set_verdict_modified(nfqueue.NF_ACCEPT, str(scapy_pkt), len(scapy_pkt)) 
    else:
        pkt.set_verdict(nfqueue.NF_ACCEPT)
    return 1
# Encrypt packets in the queue
def encrypt_pkt(num, pkt):
    data = pkt.get_data()
    scapy_pkt = IP(data)
    old_payload = str(scapy_pkt[TCP].payload)
    peer = scapy_pkt.dst
    if len(old_payload) > 0:
        peer_pad = One_time_pads[peer][0:len(old_payload)]
        new_payload = ''.join(chr(ord(p) ^ ord(c)) for p,c in zip(old_payload,peer_pad))
        scapy_pkt[TCP].remove_payload()
        scapy_pkt[TCP].add_payload(new_payload)
        del scapy_pkt[IP].chksum
        del scapy_pkt[TCP].chksum
        scapy_pkt.show2(dump=True)
        pkt.set_verdict_modified(nfqueue.NF_ACCEPT, str(scapy_pkt), len(scapy_pkt))
    else:
        pkt.set_verdict(nfqueue.NF_ACCEPT)
    return 1

class AsyncNfQueue(asyncore.file_dispatcher):
  # An asyncore dispatcher of nfqueue events.
  def __init__(self, cb, nqueue=0, family=AF_INET, maxlen=5000, map=None):
    self._q = nfqueue.queue()
    self._q.set_callback(cb)
    self._q.fast_open(nqueue, family)
    self._q.set_queue_maxlen(maxlen)
    self.fd = self._q.get_fd()
    asyncore.file_dispatcher.__init__(self, self.fd, map)
    self._q.set_mode(nfqueue.NFQNL_COPY_PACKET)

  def handle_read(self):
    self._q.process_pending(1)

  # We don't need to check for the socket to be ready for writing
  def writable(self):
    return False

def main():
    set_iptables()
    thread_server = Thread(target = setup_RSA_OTP_SIG_server, args = (my_RSA_priv_key.publickey().exportKey(format="PEM", passphrase=None, pkcs=1), ))
    thread_server.daemon = True
    thread_server.start()
    setup_RSA()
    nfqueue_encrypt = AsyncNfQueue(encrypt_pkt, nqueue=1)
    nfqueue_decrypt = AsyncNfQueue(decrypt_pkt, nqueue=2)
    os.system("bitcoin-qt")
    asyncore.loop()

main()
