def add(a, b):
    return a+b
def sub(a, b):
    return a-b
def times(a, b):
    return a*b
def floor(a, b):
    return a//b
def xor(a, b):
    return a^b
def orr(a, b):
    return a|b
def andd(a, b):
    return a&b
def bsub(a, b):
    return b-a
def fst(a, b):
    return a
def snd(a, b):
    return b
def mod(a, b):
    return a % b
    

encrypted_flag = [205, 196, 215, 218, 225, 226, 1189, 2045, 2372, 9300, 8304, 660, 8243, 16057, 16113, 16057, 16004, 16007, 16006, 8561, 805, 346, 195, 201, 154, 146, 223]

guess = input("What's the flag? ") # remember, flags start with lactf{

if (len(guess) < len(encrypted_flag)):
    print("That's too short :(")
    exit()
    
for i in range(len(encrypted_flag)-1):
    j = ord(guess[i])
    k = ord(guess[i+1])
    if (add(fst(j,k),snd(j,k)) != encrypted_flag[xor(i,mod(times(j,k),j))]):
        print("That's not the flag :(")
        exit()
    
print("That's the flag! :)")











