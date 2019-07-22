from socket import AF_INET, socket, SOCK_STREAM
from threading import Thread
import pickle
import base64

#vigenere cypher start encode and decode functions
def encode(key, clear):
    enc = []
    for i in range(len(clear)):
        key_c = key[i % len(key)]
        enc_c = chr((ord(clear[i]) + ord(key_c)) % 256)
        enc.append(enc_c)
    return base64.urlsafe_b64encode("".join(enc).encode()).decode()


def decode(key, enc):
    dec = []
    enc = base64.urlsafe_b64decode(enc).decode()
    for i in range(len(enc)):
        key_c = key[i % len(key)]
        dec_c = chr((256 + ord(enc[i]) - ord(key_c)) % 256)
        dec.append(dec_c)
    return "".join(dec)


def accept_incoming_connections():
#setup handling for incoming clients
    while True:
        client, client_address = SERVER.accept()
        print(f'{client_address} has connected')
        addresses[client] = client_address
        client_ips = [x[0] for x in addresses.values()]
        print(f'Connected IP\'s:{client_ips}')
        print('===========================================')
        Thread(target=handle_client, args=(client,)).start()

def pw_check(client_password, client):
    global clients
    client_info = client.getsockname()
    if client_password == PW:
        print(f'{client_info} Password Good')
        return True
    else:
        print(f'{client_info} Password Bad')
        data = {'message_id': 3, 'error': 'bad_pw'}
        data = pickle.dumps(data)
        client.send(data)
        client.close()
#        del clients[client]
        del addresses[client]
        return False

def handle_client(client):
    global messages
    if client in messages:
        messages[client] += 1
    else:
        messages[client] = 0
    if messages[client] < 2:
        #Check the password as it is the first piece of data that was sent.
        #so if the sending counter is less than 2 check if pw is correct
        print('Checking Password...')
        pwburst = client.recv(BUFSIZ).decode("utf8")
        pwresult = pw_check(pwburst, client)
        if pwresult == False:
            return False
    #check to make sure there is only 1 connection per IP
    client_ips = [x[0] for x in addresses.values()]
    connecting_ip = addresses[client][0]
    ipcount = client_ips.count(connecting_ip)
    if ipcount > 2:
        print(f'{addresses[client]} is already connected')
        messages[client] = 0
        data = {'message_id': 3, 'error': 'bad_ip'}
        data = pickle.dumps(data)
        client.send(data)
        client.close()
        del addresses[client]
        return False
    try:
        #This loop is for checking if the username is already present or not.
        while True:
            name = client.recv(BUFSIZ).decode("utf8")
            #Decode the encoded messages.
            name = decode(PW, name)
            connected_users = [x for x in clients.values()]
            if name not in connected_users:
                welcome_message = f'Welcome {name} If you ever want to quit, type QUIT to exit.'
                #Encode the message again before sending.
                welcome_message = encode(PW, welcome_message)
                client.send(bytes(welcome_message, "utf8"))
                #Sends a list of all current connected users
                clients[client] = name
                #serialise the user data before sending it
                users = [x for x in clients.values()]
                srl_clients = pickle.dumps(users)
                #YEEET that data over
                send_user_list(srl_clients, clients)
                broadcast(f'{name} has joined the chat!')
                break
            else:
                print(f'{name} is already taken')
                data = {'message_id': 3, 'error': 'bad_usr'}
                data = pickle.dumps(data)
                client.send(data)
    except ConnectionResetError:
        client.close()
        pass
    while True:
        try:
            msg = client.recv(BUFSIZ)
            #This part can receive either a regular string, or it can recieve a pickled dictionary, if its a dict thats a message
            #saying that someone is typing
            if msg != bytes("QUIT", "utf8"):
                try:
                    data = pickle.loads(msg)
                    if data["event"] == 'typing':
                        #Start list comprehension magic, arcane python arts of doom
                        #list of all connected address
#                        addr_list = [x for x in addresses.values()]
                        #IP and Port tuple of current typing address
#                        typing_addr = [x for x in addr_list if data["hostname"] in x]
                        #Find the client value in the addresses dict using the value we found above
#                        typing_client = [k for k,v in addresses.items() if v == typing_addr[0]]
#                        typing_username = clients[typing_client[0]]
#                        print(typing_username)
                        send_typing_info(data["hostname"], event='typing')
                    elif data["event"] == 'sent':
                        send_typing_info(data["hostname"], event='sent')
                except:
                    #The actual chat function of showing the messages
                    msg = decode(PW, msg)
                    broadcast(msg, name+": ")
        #Do this when the client leaves
            else:
                client.send(bytes("QUIT", "utf8"))
                client.close()
                del clients[client]
                del addresses[client]
                del messages[client]
                #Tell everyone to remove user from the list
                user_has_left(name, clients)
                broadcast(f'{name} has left the chat.')
                print(f'{name} has left the chat.')
                break
        #Do this when the client dc's
        except ConnectionResetError:
            print(f'{name} DC\'d rather abruptly')
            del clients[client]
            if len(clients) >= 1:
                broadcast(f'{name} got DC\'d')
                user_has_left(name, clients)
            client.close()
            break

def send_user_list(names, clients):
    unsrl_names = pickle.loads(names)
    print(f'List of connected users: {unsrl_names}')
    for sock in clients:
        sock.send(names)

def user_has_left(name, clients):
    print(f'Telling clients to delete {name}')
    #Message ID 1 means, to delete the user from the userlist on the right side.
    data = {'message_id': 1, 'user': name}
    data = pickle.dumps(data)
    for sock in clients:
        sock.send(data)

def send_typing_info(name, event):
    data = {'message_id': 2, 'event': event, 'user': name}
    data = pickle.dumps(data)
    for sock in clients:
        sock.send(data)

#This part actually sends the message to everyone
def broadcast(msg, prefix=""):
    msg = f'{prefix}{msg}'
    msg = encode(PW, msg)
    for sock in clients:
        sock.send(bytes(msg, "utf8"))

global PW, messages, clients
#usr_list = {}
clients = {}
addresses = {}
messages = {}
PW = input('Server Password: ')
HOST = ''
PORT = 33000
BUFSIZ = 1024
ADDR = (HOST, PORT)
SERVER = socket(AF_INET, SOCK_STREAM)
SERVER.bind(ADDR)

if __name__ == "__main__":
    SERVER.listen(5)  # Listens for 5 connections at max.
    print("Waiting for connection...")
    ACCEPT_THREAD = Thread(target=accept_incoming_connections)
    ACCEPT_THREAD.start()  # Starts the infinite loop.
    ACCEPT_THREAD.join()
    SERVER.close()
