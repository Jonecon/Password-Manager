import pyscrypt
import secrets
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

class KeySettings:
    __pref_n = 65536
    __pref_r = 8
    __pref_p = 1
    __pref_outLen = 32

    def __init__(self, salt=None, iv=None, n:int=None, r:int=None, p:int=None):
        if salt == None:
            self.__salt = secrets.token_bytes(32)
        else:
            self.__salt = salt
        
        if iv == None:
            self.__iv = secrets.token_bytes(16)
        else:
            self.__iv = iv

        if n == None:
            self.__n = self.__pref_n
        else:
            self.__n = int(n)
        
        if r == None:
            self.__r = self.__pref_r
        else:
            self.__r = int(r)

        if p == None:
            self.__p = self.__pref_p
        else:
            self.__p = int(p)

        self.__outLen = self.__pref_outLen
                
    def encrypt(self, masterPassword, generatedPasswordBytes:bytearray):
        aes = AES.new(self.generateKey(masterPassword.encode("utf8")), AES.MODE_CBC, self.__iv)
        return aes.encrypt(pad(generatedPasswordBytes, AES.block_size))

    def decrypt(self, masterPassword, passwordHashBytes:bytearray):
        aes = AES.new(self.generateKey(masterPassword.encode("utf8")), AES.MODE_CBC, self.__iv)
        return unpad(aes.decrypt(passwordHashBytes), AES.block_size).decode("utf8")

    def generateKey(self, key):
        return pyscrypt.hash(key, self.__salt, self.__n, self.__r, self.__p, self.__outLen)

    def requiresUpdate(self):
        if (self.__n < self.__pref_n) or (self.__r < self.__pref_r) or (self.__p < self.__pref_p):
            return True
        else:
            return False

    def outputData(self, encPassword):
        return [bytes.hex(self.__salt), bytes.hex(encPassword), bytes.hex(self.__iv), f"{self.__n}|{self.__r}|{self.__p}|{self.__outLen}"]

    def updateSettings(self, masterPW, encPassword:bytearray):
        if self.requiresUpdate():
            plainPW = self.decrypt(masterPW, encPassword)
            self.__n = self.__pref_n
            self.__r = self.__pref_r
            self.__p = self.__pref_p
            newPW = self.encrypt(masterPW, plainPW.encode("utf8"))
            return self.outputData(newPW)
        else:
            return self.outputData(encPassword)