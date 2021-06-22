import pyscrypt
import secrets
from Crypto.Random import get_random_bytes

class Account:
    __pref_n = 131072
    __pref_r = 8
    __pref_p = 1
    __pref_outLen = 64

    def __init__(self, username, password, isHashed, salt=None, ids=None, n=None , r=None, p=None):
        self.__username = username
        if ids is None:
            self.__ids = set()
        else:
            self.__ids = ids
        if salt is None:
            self.__salt = secrets.token_bytes(64)
        else:
            self.__salt = salt

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
        
        if isHashed:
            self.__password = password
        else:
            self.__password =  pyscrypt.hash(password.encode("utf8"), self.__salt, self.__n, self.__r, self.__p, self.__outLen)

    @staticmethod
    def fromHash(username, passwordHash, salt, ids, settings):
        settingsParts = settings.split('|')
        return Account(username, bytes.fromhex(passwordHash), True, bytes.fromhex(salt), ids, settingsParts[0], settingsParts[1], settingsParts[2])

    @staticmethod
    def fromPass(username, password):
        return Account(username, password, False)

    def getPassword(self):
        return bytes.hex(self.__password)
    
    def getSalt(self):
        return bytes.hex(self.__salt)

    def getUser(self):
        return self.__username

    def getIds(self):
        return self.__ids

    def getSettings(self):
        return f"{self.__n}|{self.__r}|{self.__p}|{self.__outLen}"
    
    def addId(self, id):
        self.__ids.add(id)

    def requiresUpdate(self):
        if (self.__n < self.__pref_n) or (self.__r < self.__pref_r) or (self.__p < self.__pref_p):
            return True
        else:
            return False

    def updateSettings(self, masterPW):
        if self.requiresUpdate():
            self.__n = self.__pref_n
            self.__r = self.__pref_r
            self.__p = self.__pref_p
            self.__password = pyscrypt.hash(masterPW.encode("utf8"), self.__salt, self.__n, self.__r, self.__p, self.__outLen)
    
    def verify(self, password):
        return self.__password == pyscrypt.hash(password.encode("utf8"), self.__salt, self.__n, self.__r, self.__p, self.__outLen)