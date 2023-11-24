# `````````````IMPORTS````````````````````

import argparse
import hashlib
import os
import sys
import time
from socket import *

from Crypto.Cipher import Salsa20

# ```````GLOBAL DEFINITIONS```````````````

# File upload pattern based on hash result
MD5_ALLOCATION = {
    0: [(1, 2), (2, 3), (3, 4), (4, 1)],
    1: [(4, 1), (1, 2), (2, 3), (3, 4)],
    2: [(3, 4), (4, 1), (1, 2), (2, 3)],
    3: [(2, 3), (3, 4), (4, 1), (1, 2)],
}

# Dictionary to maintain socket objects
sockList = {}
recvList = {}

"""
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
CLASS :  CLIENTSOCK

FUNCTIONATLITIES:
    -The Main function of this class is to maintain the TCP connections
     with the servers for file distribution purposes

Main Functions:
    1-createsock()
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
"""


class ClientSock:
    def __init__(self, port):
        self.port = port
        self.sock = socket(AF_INET, SOCK_STREAM)  # create an INET, STREAMing socket

    def createsock(self):
        self.sock.connect(("127.0.0.1", int(self.port)))
        return self.sock


"""
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

CLASS :  FILE MANAGEMENT

FUNCTIONATLITIES:
    -Most of the file handling with the servers is contained in this class
    -UPLOAD, DOWNLOAD and getting the LIST of the User's data

Main Functions:
    1-Upload()
    2-Download()
    3-ListFile()
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
"""


class fileMgmt:
    def __init__(self, configDetails):
        self.cDtls = configDetails
        self.ServerStat = {}
        self.error = False

    def SockInit(self):
        serverOn = []
        for key, value in self.cDtls.ServerIPs.items():
            try:
                ip, port = value.split(":")
                conn = ClientSock(port)
                Sock = conn.createsock()
                sockList[key] = Sock  # Probably need to change to dict???
                self.ServerStat[key] = "ON"
            except timeout:
                print("Socket error occured")
            except:
                print(
                    "Problem Connecting Server {}. Trying to connect other servers".format(
                        key
                    )
                )
                self.ServerStat[key] = "OFF"
        return self.ServerStat

    """
    Function: UPLOAD
    
    details: this function is used to upload the requested file 
             into the servers mentioned in the dc.conf
             
    Arguements: filename-> the filename of the one to be uploaded
    Dependent functions: FilePartition()
    """

    def Upload(self, filename):
        if not os.path.isfile(filename):
            print("This file doesnot exists. please try again")
            return
        hashVal = hashlib.md5(filename.encode())
        self.md5Value = int(hashVal.hexdigest(), 16) % 4
        self.allocationScheme = MD5_ALLOCATION[self.md5Value]
        success = self.SockInit()
        self.FilePartition(filename)

    """
    Function: FilePartition
    
    details: This is part of the upload file process. 
             the main part of the function is to prepare 
             partitions of the file before it can be 
             uploaded into respective servers
    Arguements: filename-> the uploading filename
    """

    def FilePartition(self, filename):
        fileOffset = []
        OffsetLen = []
        n = 0
        offset = 0
        fsize = os.path.getsize(filename)  # Get the size of the file
        if fsize % 4 == 0:
            while offset <= fsize:
                fileOffset.append(offset)
                OffsetLen.append(fsize / 4)
                offset = offset + fsize / 4
                n = n + 1
        else:
            fileOffset.append(0)
            fileOffset.append(int(fsize / 4) + fileOffset[0])
            fileOffset.append(int(fsize / 4) + fileOffset[1])
            fileOffset.append(int(fsize / 4) + fileOffset[2])
            OffsetLen.append(int(fsize / 4))
            OffsetLen.append(int(fsize / 4))
            OffsetLen.append(int(fsize / 4))
            OffsetLen.append(fsize - (OffsetLen[0] + OffsetLen[1] + OffsetLen[2]))

        print("Length of the file {}".format(fsize))
        print("Offsets are {}".format(fileOffset))
        print("Offset Lengths are {}".format(OffsetLen))

        # Begin the Download Process
        with open(filename, "rb") as fh:
            for key, value in sockList.items():
                # value.settimeout(1)
                try:
                    if self.ServerStat[key] == "OFF":
                        print(
                            "Unable to send to Server {}. Server might be down".format(
                                key
                            )
                        )
                        continue
                    print("Connecting to Server {}".format(key))

                    value.send("upload".encode())
                    parts2send = self.allocationScheme[key - 1]

                    fh.seek(int(fileOffset[(parts2send[0] - 1)]), 0)
                    data2send = self.prepareHeader(
                        int(OffsetLen[(parts2send[0] - 1)]),
                        parts2send[0],
                        filename,
                        fsize,
                        fileOffset[(parts2send[0] - 1)],
                    )
                    # encrypt_dat1 = self.encryptPart(data2send.encode())
                    value.send(
                        (data2send + "-" * (100 - len(data2send))).encode()
                    )  # encrypt_dat1 MACHI HERE YOU ARE SENDING LEN+8 AS LENGTH CORRECT AGI NODU
                    status = value.recv(20)
                    status = status.decode()
                    if "Error" in status:
                        print(status)
                        print("Cannot Continue")
                        return
                    BytesSent = int(OffsetLen[(parts2send[0] - 1)])
                    b2st = 0
                    while BytesSent > 0:
                        if BytesSent > 65000:
                            data = fh.read(65000)
                        else:
                            data = fh.read(BytesSent)

                        encrypt_dat11 = self.encryptPart(data)
                        value.send(encrypt_dat11)
                        # value.settimeout(1)
                        time.sleep(0.01)
                        status = ""
                        Recv_ACK = False
                        while not Recv_ACK:
                            try:
                                while status == "":
                                    status = value.recv(1)
                                    print(
                                        "Sending file part "
                                        + str(parts2send[0])
                                        + " : "
                                        + str(
                                            100
                                            - int(
                                                (
                                                    BytesSent
                                                    / int(
                                                        OffsetLen[(parts2send[0] - 1)]
                                                    )
                                                    * 100
                                                )
                                            )
                                        )
                                        + "%\r",
                                        end="",
                                    )
                                Recv_ACK = True
                            except timeout:
                                value.send(encrypt_dat11)
                                time.sleep(0.01)
                        BytesSent = BytesSent - len(encrypt_dat11) + 8
                        b2st = b2st + len(data)
                    print("Sending file part " + str(parts2send[0]) + " : 100%")
                    print(str(b2st))
                    time.sleep(0.01)
                    # value.settimeout(1)
                    fh.seek(int(fileOffset[(parts2send[1] - 1)]), 0)
                    data2send2 = self.prepareHeader(
                        int(OffsetLen[(parts2send[1] - 1)]),
                        parts2send[1],
                        filename,
                        fsize,
                        fileOffset[(parts2send[1] - 1)],
                    )
                    # encrypt_dat2 = self.encryptPart(data2send2.encode())
                    value.send((data2send2 + "-" * (100 - len(data2send2))).encode())
                    time.sleep(0.01)

                    BytesSent = int(OffsetLen[(parts2send[1] - 1)])
                    while BytesSent > 0:
                        if BytesSent > 65000:
                            data = fh.read(65000)
                        else:
                            data = fh.read(BytesSent)
                        encrypt_dat22 = self.encryptPart(data)
                        value.send(encrypt_dat22)
                        # value.settimeout(1)
                        time.sleep(0.01)
                        status = ""
                        Recv_ACK = False
                        while not Recv_ACK:
                            try:
                                while status == "":
                                    status = value.recv(1)
                                Recv_ACK = True
                            except timeout:
                                value.send(encrypt_dat22)
                                time.sleep(0.01)
                        print(
                            "Sending file part "
                            + str(parts2send[1])
                            + " : "
                            + str(
                                100
                                - int(
                                    (
                                        BytesSent
                                        / int(OffsetLen[(parts2send[1] - 1)])
                                        * 100
                                    )
                                )
                            )
                            + "%\r",
                            end="",
                        )
                        BytesSent = BytesSent - len(data)
                    print("Sending file part " + str(parts2send[1]) + " : 100%")
                    # value.settimeout(None)
                except timeout:
                    print("Server is not responding")
                    print(
                        "Problem while transferring file to Server {}".format(key + 1)
                    )
                value.settimeout(None)

    def prepareHeader(self, data, parts2send, filename, size, offset):
        data2send2 = (
            self.cDtls.username
            + "\n"
            + self.cDtls.passwd
            + "\n"
            + filename
            + "\n"
            + str(parts2send)
            + "\n"
            + str(data)
            + "\n"
            + str(size)
            + "\n"
            + str(offset)
            + "\n"
        )
        return data2send2

    """
    Function: DOWNLOAD
    
    details: this function is used to download the requested file 
             from the servers mentioned in the dc.conf
             
    Arguements: filename-> the name of the file that needs to be downloaded
    Dependent functions: SendDwnldReq
    """

    def Download(self, file):
        self.SockInit()
        foundthem = 0
        Full_Capture = False
        for i in range(1, 3):
            if self.ServerStat[i] == "ON" and self.ServerStat[i + 2] == "ON":
                foundthem = self.SendDwnldReq(sockList[i], file)
                if not self.error:
                    foundthem = foundthem + self.SendDwnldReq(sockList[i + 2], file)

            # If download failed due to any error, do not proceed
            if self.error:
                break
            # If all the chunks were captured with first 2 servers, stop looking now
            if i == 1 and foundthem == 4:
                print("Partitions found in First 2 servers : " + str(foundthem))
                break
            # if all the of the partitions could not be obtained, try the other 2 servers
            if i == 1 and foundthem != 4 and not self.error:
                print("All the chunks not received yet. Contacting other 2 servers..")
                continue
            # If above cases fail, then we can conclude, two or more servers are down
            elif foundthem != 4:
                print("All the chunks could not be obtained")
                print("2 or more servers are down. File download failed")
                Full_Capture = True

        # rearragning the acquired files and deleting the temporary files
        if not Full_Capture and not self.error:
            self.Clear_the_Mess(file)
            print("Successfully retrieved the file")

    def SendDwnldReq(self, sock, file):
        sock.send("download".encode())
        req = self.cDtls.username + "\n" + self.cDtls.passwd + "\n" + file
        sock.send((req + "-" * (100 - len(req))).encode())
        i = 0
        try:
            print("Downloading {} in progress".format(file))
            while i < 2:
                # sock.settimeout(5)
                status = sock.recv(50)
                status = status.decode()
                if "Error" in status:
                    print(status)
                    self.error = True
                    return 0

                time.sleep(1)
                len1 = sock.recv(10).strip(b"-")
                part = sock.recv(10).strip(b"-")
                len1 = len1.decode()
                len1 = len1.strip("\n")
                part = part.decode()
                part = part.strip("\n")
                sub = file.split("/")
                if len(sub) > 1:
                    subf = sub[0] + "//"
                    file1 = sub[1]
                else:
                    subf = ""
                    file1 = file
                bytesrecv = 0
                with open(subf + "Rx_" + file1 + part, "wb") as fh:
                    while bytesrecv < int(len1):
                        recvList[part] = subf + "Rx_" + file1 + part
                        data = sock.recv(65008)
                        ucsm = self.decryptPart(data)
                        sock.send("s".encode())
                        fh.write(ucsm)
                        print(
                            "Recieving part : {} => {}%\r".format(
                                part, (int((bytesrecv / int(len1)) * 100))
                            ),
                            end="",
                        )
                        bytesrecv = bytesrecv + len(data)
                print("Recieving part : {} => 100%".format(part))
                i = i + 1
            sock.settimeout(None)
            return 2  # BOSS check this
        except:
            print("Exception caught during receiving")
            return 0

    """
    Function: ENCRYPTPART
    
    details: this function is used to encrypt the data chunk 
             before sending it to the servers. the encryption standard used is
             "Salsa20" from the Cryptodome Library
             
             the encrypted data will be in the following format
             [ Encryption-Nonce + CipherText ]
             Encryption-Nonce is the key for the decryption process needed at the server
             
             
    Arguements: data-> the data chunk that needs to be encrypted
    Dependent functions: decryptPart()
    """

    def encryptPart(self, data):
        encryption_suite = Salsa20.new(PASSWD.encode())  # b'0123456789012345')
        cipher_text = encryption_suite.encrypt(data)
        key = encryption_suite.nonce
        return key + cipher_text

    def decryptPart(self, data):
        nonc = data[:8]
        encrypted = data[8:]
        decryption_suite = Salsa20.new(
            PASSWD.encode(), nonce=nonc
        )  # b'0123456789012345',nonce=nonc)
        plain_text = decryption_suite.decrypt(encrypted)
        return plain_text

    # def getpasswd(self,name):
    # return user[name]
    def ListFile(self, folder):
        self.SockInit()
        finalList = {}
        for i in range(1, 5):
            print("getting List from Server: {}".format(i))
            if self.ServerStat[i] == "ON":
                self.getfileStatus(sockList[i], finalList, i, folder)
            else:
                print("The Server-{} is down.".format(i))

        print("-" * 60)
        print(finalList)
        print("File details")
        for key, val1 in finalList.items():
            if len(finalList[key]) == 4:
                print(key + " : [Complete]")
            else:
                print(key + " : [Incomplete]")
        print("-" * 60)

    def getfileStatus(self, sock, finalList, sockname, folder):
        try:
            print("Request to Access the list of files from " + folder)
            sock.send("list".encode())
            req = self.cDtls.username + "\n" + self.cDtls.passwd + "\n" + folder
            sock.send((req + "-" * (100 - len(req))).encode())
            status = sock.recv(20)
            status = status.decode()
            if "Error" in status:
                print(status)
                return
            data = sock.recv(1000)
            flist = data.decode().split("\n")
            for every in flist:
                if every:
                    name, val = every.split()
                    val1 = val.split(",")
                    for each in val1:
                        if name not in finalList:
                            finalList[name] = []
                            finalList[name].append(each)
                        elif each not in finalList[name]:
                            finalList[name].append(each)
        except:
            print("error occured during connecting server {}".format(sockname))

    """
    Function: CLEAR_THE_MESS
    
    details: this function is used to rearrange the the files after downloading
             the chunks and will delete all the temporary files
             
             
    Arguements: file-> the name of the file whose dependencies needs to be handled
    Dependent functions: SendDwnldReq()
    """


    def Clear_the_Mess(self, file):
        sub = file.split("/")
        if len(sub) > 1:
            subf = sub[0] + "//"
            file1 = sub[1]
        else:
            subf = ""
            file1 = file
        output_file_path = subf + "Rx_" + file1
        print("Writing to => " + output_file_path)

        with open(output_file_path, "ab") as output_file:
            for part_number in sorted(recvList.keys()):
                part_file_path = subf + "Rx_" + file1 + part_number
                if os.path.isfile(part_file_path):
                    with open(part_file_path, "rb") as part_file:
                        lines = part_file.readlines()
                        for line in lines:
                            output_file.write(line)
                    os.remove(part_file_path)
                else:
                    print(f"Error: Part file not found - {part_file_path}")

        print("The File is downloaded successfully")


"""
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
CLASS :  CONFIGURATION MANAGEMENT

FUNCTIONATLITIES:
    -Retrieves details from the config file - 'dc.conf'

Main Functions:
    1-getServerDetails()
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
"""


class configMgmt:
    def __init__(self):
        self.ServerIPs = {}
        self.username = ""
        self.passwd = ""
        pass

    def getServerDetails(self):
        try:
            with open(configPath, "r") as fh:
                lines = fh.readlines()
                for each in lines:
                    if "server" in each.lower():
                        dummy, name, ip = each.split()
                        self.ServerIPs[int(name[3:])] = ip
                    if "username" in each.lower():
                        self.username = each.split()[1]
                    if "password" in each.lower():
                        self.passwd = each.split()[1]
        except:
            print(
                "There was problemm accessing the file. \
            Please check the configutration file and try again"
            )


"""
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
                MAIN FUNCTION
vvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvv
"""
if __name__ == "__main__":
    argparser = argparse.ArgumentParser(description="Client DFS Program")
    argparser.add_argument(
        "configFile",
        action="store",
        type=str,
        help=" Enter the configuration file for client",
    )
    if len(sys.argv) != 2:
        print(
            "Invalid arguements, you need to enter config file name. program now exits"
        )
        sys.exit()
    args = argparser.parse_args()

    # Get the Command Line arguements and pass to Server Class
    configPath = args.configFile

    config = configMgmt()
    config.getServerDetails()
    while 1:
        print("*" * 60)
        print("\t\tDFC CLIENT SYSTEM")
        print("\tUSERNAME: {}".format(config.username.upper()))
        print("Server IPs:")
        for key, value in config.ServerIPs.items():
            print("\t{} : {}".format(key, value))
        option = input(
            "*" * 60
            + "\n\t\tSelect the function to continue\n"
            + "1-PUT\n2-GET\n3-LIST\n"
            + "*" * 60
            + "\n"
        )
        cmd = option.split()[0]
        try:
            file = option.split()[1]
        except:
            if cmd == "LIST":
                file = ""
            else:
                print("Addtional Arguement required")
        # IMPLEMENT SUBFOLDER ACCESS MECHANISMS
        fHandler = fileMgmt(config)
        USERNAME = config.username

        # key generation from User's password for authenticated access
        if len(config.passwd) > 16:
            PASSWD = config.passwd[:16]
        else:
            PASSWD = config.passwd + "*" * (16 - len(config.passwd))

        # Execute the commands as entered by the user
        if cmd.upper() == "PUT":
            fHandler.Upload(file)
        if cmd.upper() == "GET":
            fHandler.Download(file)
        if cmd.upper() == "LIST":
            fHandler.ListFile(file)

        print("^" * 60)
        print("\t\tOperation Completed")
        print("v" * 60)
