import argparse
import fnmatch
import os
import sys
import threading
import time
from socket import *

from Crypto.Cipher import Salsa20

# Dictionary to access all the User credentials
user = {}


class Server:
    def __init__(self, folder, sport):
        self.serverPort = int(sport)  # serverPort
        self.ServerPath = os.getcwd()
        self.folder = folder[1:]
        self.user1 = ""

    def create_socket(self):
        # Creating Socket
        self.serverSocket = socket(AF_INET, SOCK_STREAM)
        self.serverSocket.bind(("", self.serverPort))
        self.serverSocket.listen()
        print("Server running on " + str(self.serverPort))
        while 1:
            conn, addr = self.serverSocket.accept()
            if conn:
                # try:
                sockthread = threading.Thread(target=self.runReq, args=(conn,))
                sockthread.start()

    def runReq(self, conn):
        print("@" * 60)
        req = conn.recv(100)
        if req.decode() == "upload":
            print("\t\tUPLOAD REQUEST")
            data1 = conn.recv(100)
            data1 = data1.strip(b"-")
            data = data1.decode()
            credentials = data.split("\n")
            name = credentials[0]
            passwd = credentials[1]
            self.user1 = name

            if not self.validateUser(name, passwd):
                print("Unauthorized access. Cannot Proceed Further")
                conn.send("Error : User Access Denied".encode())
                return
            else:
                conn.send("Access Granted".encode())
            time.sleep(1)

            time.sleep(0.01)
            self.write2file(conn, data1)
            time.sleep(0.01)
            data2 = conn.recv(100)
            data2 = data2.strip(b"-")
            time.sleep(0.01)
            self.write2file(conn, data2)

        if req.decode() == "download":
            print("\t\tDOWNLOAD REQUEST")

            request = conn.recv(50)
            request = request.decode()
            request = request.strip("-")
            user, pwd, filename = request.split("\n")
            print("User: {}".format(user))
            print("Requested File: {}".format(filename))
            if not os.path.isdir(self.folder + "//" + user):
                conn.send("Error: No such User record present in the server".encode())
                return
            # try:
            sub = filename.split("/")
            if len(sub) > 1:
                if not os.path.isdir(self.folder + "//" + user + "//" + sub[0]):
                    os.mkdir(self.folder + "//" + user + "//" + sub[0])
                subf = sub[0] + "//"
                fname = sub[1]
            else:
                subf = ""
                fname = filename
            foundFlag = False
            for each in os.listdir(self.folder + "//" + user + "//" + subf):
                if fnmatch.fnmatch(each, "." + fname + ".[0-4]"):
                    foundFlag = True
                    cipher1 = self.GetcipherKey(user)
                    with open(
                        self.folder + "//" + user + "//" + subf + each, "rb"
                    ) as fh:
                        conn.send("File Found No Issues found".encode())
                        time.sleep(1)
                        lines = fh.readlines()
                        print(
                            "File found: {} of size {} bytes".format(
                                each, lines[0].decode().strip("\n")
                            )
                        )
                        conn.send(lines[0])
                        time.sleep(0.1)
                        conn.send(lines[1])
                        time.sleep(0.1)
                        off_len = len(lines[0]) + len(lines[1])
                        fh.seek(off_len)
                        BytesToSend = 0
                        while BytesToSend < int(lines[0].decode()):
                            data = fh.read(65000)
                            secret = self.encrypt1(data, cipher1)
                            conn.send(secret)
                            time.sleep(0.1)
                            status = ""
                            Recv_ACK = False
                            while not Recv_ACK:
                                try:
                                    while status == "":
                                        status = conn.recv(1)
                                    print(
                                        "Sending: "
                                        + str(int((BytesToSend / int(lines[0])) * 100))
                                        + "%\r",
                                        end="",
                                    )
                                    Recv_ACK = True
                                except timeout:
                                    conn.send(secret)
                                    time.sleep(0.01)
                            BytesToSend = BytesToSend + 65000
            if foundFlag == False:
                conn.send("Error No File Found found".encode())
            print("Sending: 100%")

        if req.decode() == "list":
            filelist = {}
            print("\tLIST REQUEST")
            request = conn.recv(50)
            request = request.decode()
            request = request.strip("-")
            user, pwd, folder = request.split("\n")
            if folder:
                folder = "//" + folder
            else:
                folder = ""
            print("Sub Folder is " + folder)
            print("Entered List request")
            if not os.path.isdir(self.folder + "//" + user + folder):
                conn.send("Error: No such User record present in the server ".encode())
                time.sleep(1)
            for each in os.listdir(self.folder + "//" + user + folder + "//"):
                if fnmatch.fnmatch(each, ".*.[0-4]"):
                    filename = each.split(".")
                    name = filename[1] + "." + filename[2]
                    part = filename[3]
                    if name not in filelist:
                        filelist[name] = part
                    else:
                        filelist[name] = filelist[name] + "," + part
            flist = ""
            for key, value in filelist.items():
                flist = flist + key + " " + str(value) + "\n"
            conn.send("Sending the List now".encode())
            print(flist)
            conn.send(flist.encode())
            time.sleep(0.1)

        print("~" * 60)

    def write2file(self, conn, data1):
        data = data1.decode()
        details = data.split("\n")
        name = details[0]
        passwd = details[1]
        fname = details[2]
        part = details[3]
        length = details[4]

        print("User: {}".format(name))
        print("File Upload: {} part-{} Length-{}".format(fname, part, length))

        if not os.path.isdir(self.folder + "/" + name):
            os.makedirs(self.folder + "/" + name)
        sub = fname.split("/")
        if len(sub) > 1:
            if not os.path.isdir(self.folder + "//" + name + "//" + sub[0]):
                os.mkdir(self.folder + "//" + name + "//" + sub[0])
            subf = sub[0] + "//"
            fname = sub[1]
        else:
            subf = ""
        received = 0
        with open(
            self.folder + "//" + name + "//" + subf + "." + fname + "." + part, "wb"
        ) as fh:
            fh.write((length + "\n").encode())
            fh.write((part + "\n").encode())

            while received < int(length):
                content2 = conn.recv(65008)
                key1 = self.GetcipherKey(name)
                decryptData = self.decrypt1(content2, key1)
                conn.send("s".encode())
                fh.write(decryptData)
                received = received + len(content2) - 8
        print("Upload Complete")

    def encrypt1(self, data, key1):
        encryption_suite = Salsa20.new(key1)
        cipher_text = encryption_suite.encrypt(data)
        key = encryption_suite.nonce
        return key + cipher_text

    def decrypt1(self, data, key1):
        nonc = data[:8]
        encrypted = data[8:]
        decryption_suite = Salsa20.new(key1, nonce=nonc)
        plain_text = decryption_suite.decrypt(encrypted)
        # print(plain_text)
        return plain_text

    def GetcipherKey(self, name):
        passwd1 = user[name]
        if len(passwd1) > 16:
            PASSWD = passwd1[:16]
        else:
            PASSWD = passwd1 + "*" * (16 - len(passwd1))
        return PASSWD.encode()

    def GetUserDetails(self):
        try:
            with open("ds.conf", "r") as fh:
                lines = fh.readlines()
                for each in lines:
                    if each:
                        name, password = each.split()
                        user[name] = password
            print(user)
        except:
            print("Valid Conf file is not present in the System")

    def validateUser(self, name, password):
        if name in user.keys():
            if user[name] == password:
                print("Access Granted")
                return True
            else:
                return False
        else:
            return False

    def getEncryptionKey(self, name):
        return user[name]


if __name__ == "__main__":
    argparser = argparse.ArgumentParser(description="Server Hosting Program")
    argparser.add_argument(
        "Server_Folder",
        action="store",
        type=str,
        help=" Enter the Folder for the Server",
    )
    argparser.add_argument(
        "ServerPort", action="store", type=int, help=" Enter the Port Number"
    )
    if len(sys.argv) != 3:
        print("Invalid arguments, you need to enter Folder and Part. program now exits")
        sys.exit()
    args = argparser.parse_args()

    # Get the Command Line arguments and pass to Server Class
    MyFolder = args.Server_Folder
    SPort = args.ServerPort

    if not os.path.isdir(MyFolder[1:]):
        os.mkdir(MyFolder[1:])

    server1 = Server(MyFolder, SPort)

    # Fetch the User credentials before beginning
    server1.GetUserDetails()
    server1.create_socket()
