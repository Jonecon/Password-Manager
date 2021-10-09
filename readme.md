#Password Manager
As a project we were asked to make a Password Manager in a language of our choice. I chose to implement this in python, as I needed to learn the language for another project. This project used scrypt to increase the computational time of the hashing in order to increase the time it would take to brute force a hash. The users Masterpassword is run through this process to create a key, and then any generated passwords are run through this process and stored using the users key.

**Compiler Choice**
-
 - I used pypy3 to run compile the program
 - pypy3 login time: 0.934s
 - CPython login time: 76.402s
 
 **pypy3 Setup ubuntu**
-
 installation steps:
 - sudo apt install pypy3
 - sudo apt-get install pip
 - sudo apt-get install pypy3-dev
 - pypy3 -m pip install pyscrypt
 - pypy3 -m pip install pycryptodome

Usage:
 - pypy3 PasswordManager.py
