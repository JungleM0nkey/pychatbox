#from socket import AF_INET, socket, SOCK_STREAM
from socket import *
from threading import Thread
from tkinter import *
from tkinter.font import Font, nametofont
from tkinter import ttk
import pickle
import getpass
import os
import json
import base64


#STEP 1
def startup(config_elements):
    #start the gui make
    startpanel = Tk()
    startpanel.title("M0nkeys PyChat")
    startpanel.resizable(width=False, height=False)
    startpanel.geometry("362x111+900+520")
    #select theme
    clamstyle = ttk.Style(startpanel)
    clamstyle.theme_use('clam')
    clamstyle.configure('TSizegrip', background='#F0F0F0')
    #start host area
    host_label = Label(startpanel, text='SERVER : ')
    host_label.grid(padx=(2,0),pady=(10,0),sticky=W)
    host_entry = ttk.Combobox(startpanel, width=41, values=config_elements["host_list"])
    host_entry.grid(row=0,column=0,padx=(80,0),pady=(10,0),sticky=E+W)
    host_entry.set(config_elements["current_host"])
    num = len(config_elements["current_host"])
    host_entry.icursor(num)
    startpanel.focus_force()
    #start pw area
    pw_label = Label(startpanel, text='PASSWORD : ')
    pw_label.grid(row=1,padx=(2,0),pady=(10,0),sticky=W)
    pw_entry = ttk.Entry(startpanel,width=42, show="*")
    pw_entry.grid(row=1,column=0,padx=(80,0),pady=(10,0),sticky=E+W)
    pw_entry.focus()
#    login_button = Button(startpanel, text='Login',width=10,relief=RIDGE, command=lambda: root(startpanel, pw_entry, host_entry))
    login_msg = Label(startpanel,  text='')
    login_msg.grid(column=0, row=2,pady=(10,0),padx=(25,0),sticky=W)
    login_msg.config(fg="red")
    login_button = ttk.Button(startpanel, text='Login',width=10, command=lambda: connect_and_verify(config_elements, startpanel, pw_entry, host_entry,login_msg))
    login_button.grid(column=0,row=2,padx=(130,0),pady=(10,0),sticky=W)
    exit_button = ttk.Button(startpanel, text='Exit',width=10, command=lambda: window_kill(startpanel))
    exit_button.grid(column=0,row=2,padx=(180,0),pady=(10,0))
#    pw_entry.bind("<Return>", lambda x:root(startpanel, pw_entry, host_entry))
    pw_entry.bind("<Return>", lambda x:connect_and_verify(config_elements, startpanel, pw_entry, host_entry, login_msg))
    startpanel.mainloop()


#STEP 2
def connect_and_verify(config_elements, startpanel, pw_entry, host_entry, login_msg):
    global host_password
    #Get info to use to connect
    host_name = host_entry.get()
    host_password = pw_entry.get()
    settings_file = 'config.json'
    #Add new host to the config file if it has not already been visited before
    if host_name not in config_elements["host_list"]:
        with open(settings_file, 'w') as json_file:
            config_elements["host_list"].append(host_name)
            json.dump(config_elements, json_file)
    #Take the host entry entered and save it to be in the entry field for next time
    with open(settings_file, 'w') as json_file:
            config_elements["current_host"] = host_name
            json.dump(config_elements, json_file)
    #destroy old window
    startpanel.withdraw()
    #start chat window
    root(config_elements, host_name, host_password, startpanel, login_msg)


#STEP 3
def root(config_elements, host_name, host_password, startpanel, login_msg):
    #grab dem window positions and size
    geometry = config_elements["geometry"]
    x = config_elements["x_pos"]
    y = config_elements["y_pos"]
    width = config_elements["width"]
    height = config_elements["height"]
    #destroy the login window
    global top, entry_field, msg_list, usr_list, typing
    top = Toplevel(startpanel)
    top.title("M0nkeys PyChat")
    top.geometry(f"{geometry}")
    top.minsize(height=279, width=497)
    my_msg = StringVar()  # For the messages to be sent.
    my_msg.set("")
    scrollbar = ttk.Scrollbar(top, orient="vertical")
    scrollbar.grid(column=9,sticky=N+S+E,rowspan=3)
    msg_list = Listbox(top,height=25,width=65,yscrollcommand=scrollbar.set,selectmode=SINGLE,relief=FLAT)
    msg_list.grid(columnspan=9,sticky=E+W+S+N,row=0)
    msg_list.insert(END, 'Greetings from the chat box! Type your name and press ENTER')
    msg_list.bind("<1>", do_nothing)
    scrollbar.config(command=msg_list.yview)
    usr_list = Listbox(top,height=25, width=20,relief=FLAT)
    usr_list.grid(sticky=S+N,row=0,column=10)
    size_scale = ttk.Scale(top,from_=0, to=10, orient=HORIZONTAL, command= lambda x:scale_window(size_scale, msg_list))
    size_scale.grid(column=10,row=2,pady=(0,16))
    size_scale.set(5)
    entry_field = ttk.Entry(top, textvariable=my_msg)
    entry_field.bind("<Return>", send)
    entry_field.grid(row=2,column=0,sticky=W+E,padx=(6,0),pady=(0,15),columnspan=5)
    entry_field.focus()
    top.focus_force()
    typing = Label(top, text='',font=("TkDefaultFont", 9, 'italic'))
    typing.grid(row=1,column=0,sticky=W,padx=(5,0))
    send_button = ttk.Button(top, text="Send", command=send,width=10)
    send_button.grid(row=2,column=6,sticky=E,pady=(0,15),padx=(6,6))
    top.protocol("WM_DELETE_WINDOW", lambda:on_closing(top, my_msg))
 #   top.bind("<Configure>", lambda x:resize(top))
    #Send password to server and connect to server
    socket_connect(host_name, host_password, top, startpanel, login_msg)
    top.grid_columnconfigure(0,weight=1)
    top.grid_columnconfigure(2,weight=1)
    top.grid_columnconfigure(4,weight=1)
    top.grid_rowconfigure(0, weight=1)
    statustext = Label(top, bd=1, relief=SUNKEN,anchor=E)
    statustext.grid(sticky=W+E,columnspan=11,row=3)
    sg = ttk.Sizegrip(top)
    sg.grid(row=3,column=10,sticky=E)
    top.mainloop()

#STEP 4
def socket_connect(host_name, host_password, top, startpanel, login_msg):
    global client_socket, BUFSIZ
    HOST = host_name
    PW = host_password
    PORT = ''
    if not PORT:
        PORT = 33000
    else:
        PORT = int(PORT)
    BUFSIZ = 1024
    ADDR = (HOST, PORT)
    client_socket = socket(AF_INET, SOCK_STREAM)
    try:
        client_socket.connect(ADDR)
        receive_thread = Thread(target=receive, args=(top, startpanel, login_msg)).start()
        client_socket.send(bytes(PW, "utf8"))
    except:
        print(f'Server address \'{host_name}\' wrong. Failed to connect')
        top.destroy()
        startpanel.deiconify()
        login_msg.config(text="Wrong Host")


#    receive_thread.start()


################################################################################

def window_kill(startpanel):
    startpanel.destroy()

def scale_window(size_scale, msg_list):
    num = size_scale.get()
    if num == 10:
        msg_list.config(font=("TkDefaultFont", 15))
    elif num == 9:
        msg_list.config(font=("TkDefaultFont", 14))
    elif num == 8:
        msg_list.config(font=("TkDefaultFont", 13))
    elif num == 7:
        msg_list.config(font=("TkDefaultFont", 12))
    elif num == 6:
        msg_list.config(font=("TkDefaultFont", 11))
    elif num == 5:
        msg_list.config(font=("TkDefaultFont", 10))
    elif num == 4:
        msg_list.config(font=("TkDefaultFont", 9))
    elif num == 3:
        msg_list.config(font=("TkDefaultFont", 8))
    elif num == 2:
        msg_list.config(font=("TkDefaultFont", 7))
    elif num == 1:
        msg_list.config(font=("TkDefaultFont", 6))

def receive(top, startpanel, login_msg):
    global userinfo_received, host_password, client_username, message_count
    typing_list = []
    #Receieve the data and de-serialise it
#    srl_users = client_socket.recv(BUFSIZ)
#    users = pickle.loads(srl_users)
#    msg_list.insert(END, f'Welcome {users[-1]} If you ever want to quit, type QUIT to exit.')
    while True:
        try:
            msg = client_socket.recv(BUFSIZ)
            #Check if the data is pickled or not, if its pickled that means its userdata and not a message
            #It will append the username to the userlist
            try:
                data = pickle.loads(msg)
                #If item is a dictionary then delete the user from the list
                #ID 1 is user list being sent
                if type(data) is dict and data["message_id"] == 1:
                    print(f'Removing {data["user"]} from list')
                    name_list = usr_list.get(0, END)
                    padded = "       "+data["user"]
                    name_index = name_list.index(padded)
                    usr_list.delete(name_index)
                #ID 2 is just info that someone else is typing, or multiple people due to some list magic
                elif type(data) is dict and data["message_id"] == 2 :
                    if data["event"] == 'typing':
                        if data["user"] not in typing_list:
                            typing_list.append(data["user"])
                            typing_list_joined = ', '.join(typing_list)
                        typing.config(text=f'{typing_list_joined} is typing...')
                    elif data["event"] == 'sent':
#                so here when someone is done typing they will be removed from the typing list and no longer shown
                        if len(typing_list) > 0:
                            typing_list.remove(data["user"])
                            typing_list_joined = ', '.join(typing_list)
                            typing.config(text=f'{typing_list_joined} is typing...')
                            if len(typing_list) == 0:
                                typing.config(text='')
                #ID 3 is an error, this this case the error is bad password
                elif type(data) is dict and data["message_id"] == 3 and data["error"] == 'bad_pw':
                    print('Bad Password')
                    client_socket.close()
                    top.destroy()
                    login_msg.config(text="Wrong Password")
                    startpanel.deiconify()
                elif type(data) is dict and data["message_id"] == 3 and data["error"] == 'bad_usr':
                    print('Username taken')
                    msg_list.insert(END, 'Username already taken, please choose another username.')
                    msgs = msg_list.get(0, "end")
                    msgs_len = len(msgs)
                    msgs_len = msgs_len - 1
                    msg_list.itemconfig(msgs_len, foreground="red")
                    client_username = ''
                    message_count = 0
                elif type(data) is dict and data["message_id"] == 3 and data["error"] == 'bad_ip':
                    print('Client already connected from this IP')
                    client_socket.close()
                    top.destroy()
                    login_msg.config(text="1 Client per IP")
                    startpanel.deiconify()
                #if item is a list then add the user to the list
                elif type(data) is list:
                    usr_list.delete('0', 'end')
                    for user in data:
                        user = "       "+user
                        usr_list.insert(END, user)
                    #After u get the user list, allow sending the typing status to everyone else
                    entry_field.bind('<KeyPress>', lambda x:typing_event(sent=False, event=None))
            except:
            #If its a regular message it wil just throw it into the chat box
                msg = msg.decode("utf8")
                msg = decode(host_password, msg)
                if msg == 'QUIT':
                    client_socket.send(bytes("QUIT", "utf8"))
                    print('Disconnecting.')
                    client_socket.close()
                    top.destroy()
#                    login_msg.config(text="Wrong Password")
#                    startpanel.deiconify()
                else:
                    print(f'{msg}')
                    msg_list.insert(END, msg)
        except OSError:  # Possibly client has left the chat.
            break


def send(event=None):
    global message_count, client_username, host_password
    msg = entry_field.get()
    if msg == 'QUIT':
        pass
    else:
        msg = encode(host_password, msg)
    entry_field.delete(0, END) #clears the field
    client_socket.send(bytes(msg, "utf8"))
    if message_count != 0:
        typing_event(sent=True, event=None)
    #If the client hasnt sent a message yet, then use that message as the client name
    if message_count == 0:
        client_username = decode(host_password,msg)
    message_count += 1
    if msg == "QUIT":
        client_socket.close()
        print('Client Socket Closed')
        print('Window Destroyed')
        print('Exiting Program')
        top.destroy()
        exit()



def on_closing(top, my_msg, event=None):
    #call this when the window is closed
    dump_geometry(top)
    my_msg.set("QUIT")
    send()

def typing_event(sent, event=None):
    if sent == False:
        #send this dict if you are typing
        msg={'message_id': 2, 'event': 'typing', 'hostname': client_username}
    elif sent == True:
        #send this dict if you just sent the message
        msg={'message_id': 2, 'event': 'sent', 'hostname': client_username}
    msg = pickle.dumps(msg)
    client_socket.send(msg)

def do_nothing(event):
    return "break"

def dump_geometry(top):
#    geometry = resize()
#    geometry = geometry[0]
#    window_width = resize()
#    window_width = window_width[1]
#    window_height = resize()
#    window_height = window_height[2]
    top.update_idletasks()
    geometry = top.winfo_geometry()
    width = top.winfo_width()
    height = top.winfo_height()
    print(f'Dumping window size and position: {geometry}')
    with open('config.json') as json_file:
        config_elements = json.load(json_file)
        config_elements['geometry'] = geometry
        config_elements['height'] = height
        config_elements['width'] = width
    with open('config.json', 'w') as json_file:
        print(f'Saving geometry to file: {config_elements}')
        json.dump(config_elements, json_file)
    dump_position(top)
    #Old pickle code, pickle sucks, json looks better idk
#    with open(f'settings.pkl','rb') as config_file:
#        config_elements = pickle.load(config_file)
#        config_elements['geometry'] = geometry
#        config_elements['height'] = window_height
#        config_elements['width'] = window_width
#    with open(f'settings.pkl', 'wb') as config_file:
#        pickle.dump(config_elements, config_file)
#    root.destroy()

def dump_position(top):
    geometry = top.winfo_geometry()
    window_x = top.winfo_x()
    window_y = top.winfo_y()
    with open('config.json') as json_file:
        config_elements['geometry'] = geometry
        config_elements['x_pos'] = window_x
        config_elements['y_pos'] = window_y
    with open('config.json', 'w') as json_file:
        json.dump(config_elements, json_file)
#    return window_x,window_y,window_width,window_height

def resize(top):
    top.update_idletasks()
    geometry = top.winfo_geometry()
    width = top.winfo_width()
    height = top.winfo_height()
    return geometry,width,height

#################################################################################
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

#aes encryption functions
def aes_encode(message):
    with open('sfky_cnfg.pkl','rb') as config_file:
        config_elements = pickle.load(config_file)
    iv = config_elements["aes_iv"]
    obj = AES.new(master_key_str, AES.MODE_CFB, iv)
    return base64.urlsafe_b64encode(obj.encrypt(message))


def aes_decode(cipher):
    with open('sfky_cnfg.pkl','rb') as config_file:
        config_elements = pickle.load(config_file)
    iv = config_elements["aes_iv"]
    obj2 = AES.new(master_key_str, AES.MODE_CFB, iv)
    return obj2.decrypt(base64.urlsafe_b64decode(cipher))





#################################################################################
global message_count, client_username
message_count = 0
client_username = ''
#Create json config file if it does not exist
settings_file = 'config.json'
if os.path.isfile(settings_file):
        with open(settings_file) as json_file:
            config_elements = json.load(json_file)
            for element in config_elements:
                print(f'{element} : {config_elements[element]}')
            print('Client Configuration Loaded')

else:
        with open(settings_file, 'w') as json_file:
            config_elements = {
                                'geometry':'780x420+900+520',
                                'width':'780',
                                'height':'420',
                                'x_pos':'900',
                                'y_pos':'520',
                                'host_list':['localhost'],
                                'current_host':'localhost'
                               }
            json.dump(config_elements, json_file)#If json config file exists then read it
#forward the window elements into the startup function

startup(config_elements)
