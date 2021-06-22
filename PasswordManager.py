from genericpath import isfile
from hmac import new
import re
import string
import getpass
import json
import secrets
from Account import Account
from KeySettings import KeySettings

def createAccount(userName):
    data = None
    if isfile('./data/data.json'):
        try:
            with open('./data/data.json', 'r', newline='') as fr:
                data = json.load(fr)
                if data.get(userName) is None:
                    data[userName] = []
                    saveAccount(data, userName)
                else:
                    print("Username taken\n")
        except:
                data = {}
                data[userName] = []
                saveAccount(data, userName)
    else:
        data = {}
        data[userName] = []
        saveAccount(data, userName)
    del(data)

def saveAccount(data, userName):
    pw = getpass.getpass("Enter your password: ")

    #Checks to see if master password is strong
    containsLowerLetter = re.search('[a-z]', pw)
    containsUpperLetter = re.search('[A-Z]', pw)
    containsDigit = re.search('\d', pw)
    containsSpecialChar = re.search(f'[{re.escape(string.punctuation)}]', pw)

    #Check that all the checks pass
    if containsLowerLetter is None or containsDigit is None or containsSpecialChar is None or containsUpperLetter is None:
        print("Your password must contain a upper and lower case letter, a digit, and a special character.")
        createAccount(userName)
    elif len(pw) < 8: #Check to see if the password is a reasonable length
        print("Your password must be at least 8 characters.")
        createAccount(userName)
    else: #User password meets requiresments
        #Make sure the user has entered the correct password by getting them to confirm it.
        confirmPw = getpass.getpass("Confirm your password: ")
        if confirmPw != pw:
            print("Passwords don't match")
            createAccount(userName)
        else:    
            user = Account.fromPass(userName, pw)
            data[userName].append(user.getPassword())
            data[userName].append(user.getSalt())
            data[userName].append(user.getSettings())
            with open('./data/data.json', 'w', newline='') as fw:
                json.dump(data, fw)
            print(f"Successfully created account: {userName}")
            del(user)
        del(confirmPw)
    del(pw)

def login(user):
    if isfile('./data/data.json') == False:
        noData()
    
    try:
        with open('./data/data.json', 'r', newline='') as fa:
            data = json.load(fa)
            findUser = data.get(user)
            if findUser is not None:
                #Get user details
                passHash = findUser[0]
                passSalt = findUser[1]
                settings = findUser[2]
                ids = set()

                #Get the ids stored on this user
                for i in range(3, len(findUser)):
                    for key in findUser[i].keys():
                        ids.add(key)

                #Create account.
                userAcc = Account.fromHash(user, passHash, passSalt, ids, settings)

                #Verify user
                pw = getpass.getpass("Enter your password: ")
                if userAcc.verify(pw):
                    #Check if the password settings are out of date
                    if (userAcc.requiresUpdate()):
                        userAcc.updateSettings(pw)
                        settings = userAcc.getSettings()
                        passHash = userAcc.getPassword()
                        data.get(user)[0] = passHash
                        data.get(user)[2] = settings
                        with open('./data/data.json', 'w', newline='') as fw:
                            json.dump(data, fw)

                
                    del(data)
                    del(pw)
                    return userAcc
                else:
                    print("Incorrect Login")
                    del(pw)
                    del(data)
                    del(userAcc)
                    return None

            else:
                print("Incorrect Login")
                del(data)
                return None
    except Exception as e:
        print(e)
        noData()


def generatePassword(size):
    alphabet = string.ascii_letters + string.digits + string.punctuation
    pw = ''.join(secrets.choice(alphabet) for i in range(size))
    containsLowerLetter = re.search('[a-z]', pw)
    containsUpperLetter = re.search('[A-Z]', pw)
    containsDigit = re.search('\d', pw)
    containsSpecialChar = re.search(f'[{re.escape(string.punctuation)}]', pw)
    if containsLowerLetter is not None and containsDigit is not None and containsSpecialChar is not None and containsUpperLetter is not None:
        return pw
    else:
        return generatePassword(size)

def storePassword(id, password, user):
    #Check that this is a unique ID
    if str(id) not in user.getIds():
        #Encrypt the password before storing
        key = getpass.getpass("Enter your password: ")

        if user.verify(key) == False:
            print("Incorrect Password, failed to store password.")
            return None
        #Generate our key variables.
        scryptKey = KeySettings()
        user.addId(id)
        data = None
        try:
            with open('./data/data.json', 'r', newline='') as fr:
                data = json.load(fr)
                data[user.getUser()].append({
                    id:scryptKey.outputData(
                        scryptKey.encrypt(key, password.encode("utf8"))
                        )
                    })

            with open('./data/data.json', 'w', newline='') as fw:
                json.dump(data, fw)
        except:
            print("File corrupt, cannot read data.")
            corrupt()
        
        #Double check memory is being cleaned up
        del(password)
        del(data)
        del(scryptKey) 
    else:
        print("This id is already in use")
        del(password)


def retrievePassword(id, user):
    data = None
    #Get the password from the local file.
    try:
        with open('./data/data.json', 'r', newline='') as fr:
            data = json.load(fr)
    except:
        print("Corrupted data file.")
        corrupt()
    
    if data is None:
        print("No password could be retrieved.")
        return None

    #Get information for this id
    idInfo = data.get(user.getUser())
    found = False
    index = 2
    for i in range(3, len(idInfo)): 
        index += 1
        if idInfo[i].get(id) is not None:
            salt = bytes.fromhex(idInfo[i].get(id)[0])
            passwordBytes = bytes.fromhex(idInfo[i].get(id)[1])
            iv = bytes.fromhex(idInfo[i].get(id)[2])
            stringSettings = idInfo[i].get(id)[3]
            found = True
            break
    
    if found == False:
        print("Cannot find id")
        return None

    pw = getpass.getpass("Enter your password: ")
    if user.verify(pw) == False:
        print("Incorrect Password, failed to retrieve password.")
        return None
    
    #Setup key settings
    stringSettingsParts = stringSettings.split('|')
    scryptKey = KeySettings(salt, iv, stringSettingsParts[0], stringSettingsParts[1], stringSettingsParts[2])

    #Check if the password is encrypted using up to date hash settings
    if(scryptKey.requiresUpdate()):
        settings = scryptKey.updateSettings(pw, passwordBytes)
        with open('./data/data.json', 'w', newline='') as fw:
            for j in range(len(settings)):
                data.get(user.getUser())[index].get(id)[j] = settings[j]

            passwordBytes = bytes.fromhex(settings[1])
            json.dump(data, fw)
            

    #Decrypt the wanted password with the masterpassword.
    password = scryptKey.decrypt(pw, passwordBytes)
    del(data)
    del(pw)
    del(scryptKey)
    return  password
    
#Function that get called when there is no data, and asks the user if they think this is a mistake and wish to attempt
#to restore the data.
def noData():
    print("No data in file, try create a account first.")
    ans = input("If this is an error would you like to try restore from a backup file? y | n\n")
    if ans.lower() == 'y':
        corrupt()

#Function that is called when the user thinks the main file is missing data.
def corrupt():
    print("Attempting to restore file from backup")
    data = None
    try:
        with open('./data/backup.json', 'r', newline='') as fr:
            data = json.load(fr)
        with open('./data/data.json', 'w', newline='') as fw:
            json.dump(data, fw)
        print("Successfully restored file from backup.")
    except:
        print("Failed to backup")
        ans = input("Would you like to create a new account? y | n\n")
        if ans.lower() == 'y':
            ans = input("Enter your desired username: ").lower()
            createAccount(ans)

#Backs up the data to another json file in case something weird happens with the main file.
#Json file should also be backed up by the user.
def backup():
    try:
        print("Backing up data")
        data = None
        with open('./data/data.json', 'r', newline='') as fr:
            data = json.load(fr)
        with open('./data/backup.json', 'w', newline='') as fw:
            json.dump(data, fw)
    except:
        print("Backup failed")


#Is the main loop of the program, will get user input and switch between logged in and logged out states.
def main():
    user = None
    quit = False
    userName = None

    if isfile('./data/data.json') == False:
        #Initial file setup.
        noData()

    while user is None and quit is False:
        print("\nCommands are:\n==========================================\nLogin (l)\nCreate Account (c)\n\nQuit Application (q)\n==========================================\n")
        ans = input("Enter command: ").lower()

        if ans == "l":
            user = login(input("\nEnter Username: ").lower())
            backup()
        elif ans == "c":
            createAccount(input("\nEnter your username: ").lower())
        elif ans == "q":
            quit = True
            backup()

    userName = user.getUser()
    while quit is False:
        print(f"\nLogged in as {userName}")
        print("Commands are:\n==========================================\nGenerate Password (g)\nRetrieve Password (r)\n\nLogout (l)\nQuit Application (q)\n==========================================\n")
        ans = input("Enter command: ").lower()

        if ans == "g":
            ans = input("\nEnter the size of the password you wish to generate: ")
            testDigit = re.fullmatch('^\d*$', ans)
            if testDigit is None:
                print("Please enter an integer for password size")
            else:
                pwSize = int(ans)
                if pwSize >= 8 and pwSize <= 80:
                    pw = generatePassword(pwSize)
                    print(f'\n{pw}\n')
                    ans = input("Do you wish to save this password: y | n\n")
                    if (ans.lower() == 'y'):
                        ans = input("\nEnter unique id for password:").lower()
                        storePassword(ans, pw, user)
        
        elif ans == "r":
            id = input("\nEnter the ID of the password you want to retieve: ").lower()
            print("Retrieving password with id: ", id)
            print(f'\n{retrievePassword(id, user)}\n')

        elif ans == "l":
            del(user)
            user = None
            backup()
            main()
            break

        elif ans == "q":
            quit = True
            backup()

#Entry point to the program.
if __name__ == "__main__":
    main()