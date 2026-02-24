"""
Virtua-Royd!
To find the real flags on our host machine, run the following command:
`TODO`

NoOrientation CTF - 2026
written by Adrian Carpio, CSSA
"""

from random import randint, choice
from time import sleep

# constants
FLAG1 = "not-the-flag{1-test-flag}" # find me!
FLAG2 = "not-the-flag{2-test-flag}" # find me!
FLAG3 = "not-the-flag{3-test-flag}" # find me!

TEXTS = {
    "welcome": "Welcome to Virtua-Royd v0.1! Type 'help' for a list of commands.",
    "help": """Virtua-Royd v0.1

    - 'insert <coin>' - Insert a coin. <coin> must be one of 10c, 20c, 50c, $1, or $2.
    - 'show' - Displays the drinks in each slot and the price and quantity of each. Also displays the current balance.
    - 'buy <row> <col>' - If enough money is in the balance and there is still stock, the drink in the chosen slot is dispensed.
        <row> must be one of 'ABCD', and <col> must be one of '1234'.
    
    Admin Commands:
    - 'unlock <key>' - Unlocks the vending machine if the key matches the lock. <key> must be a 64-bit integer.
    - 'cointray' - Displays the coin tray if the vending machine is unlocked. 
    - 'refill <row> <col>' - manifests one can of the corresponding drink and adds it to the chosen slot. 

    - 'exit' - closes the vending machine

We also have vending machines in the Skaidrite Darius and Hanna Neumann buildings if you'd like a more substantial refreshment!""",

    "insert-fail": "This coin {coin} is invalid! Please insert one of 10c, 20c, 50c, $1 or $2.",
    "insert-good": "Inserted {coin} into the machine. The balance is now ${bal:.2f}",

    "buy-fail-fmt": "The slot '{row}{col}' is invalid! Type 'help' to view the correct format.",
    "buy-fail-stk": "The drink {drink} ({row}{col}) is out of stock...",
    "buy-fail-bal": "The current balance ${bal:.2f} is not enough for the drink {drink}. Please insert more coins.",
    "buy-good": "You have bought the drink {drink}. The current balance is ${bal:.2f}. \n    [{desc}]",

    "unlock-fail-key": "The key {key} did not work. Please try again.",
    "unlock-fail-lck": "The vending machine is already unlocked.",
    "unlock-good": "The vending machine has been unlocked.",

    "cointray-fail": "The vending machine is locked.",

    "refill-fail-lck": "The vending machine is locked.",
    "refill-fail-fmt": "The slot '{row}{col}' is invalid! Type 'help to view the correct format.",
    "refill-fail-amt": "The slot '{row}{col}' is full (15 drinks)!",
    "refill-good": "Added one {drink} to slot {row}{col}. There are now {cnt} {drink}(s).",

    "bad-fmt": "Invalid command/format.",

    "exit": "Thanks for using Virtua-royd!"
}

class Drink:
    """
    Represents the drinks that `Virtuaroyd` will sell.
    """
    def __init__(self, name: str, price: int, desc: str, icon: str):
        self.name = name
        self.price = price
        self.desc = desc
        self.icon = icon

EMPTY = Drink("Empty", 0, "how did u even order this", '.')

WATER = Drink("Water", 1.50, "time to drink water :3", "W")
ELECTRON = Drink("Electron", 2.00, "just electrons, handpicked from the Amazon rainforest", "E")
SPONSODA = Drink("Spon-Soda", 5.50, "imagine we got sponsored by some drink company and ur drinking their drink rn :p", "S")
INK = Drink("Printer Ink", 9_999.99, f"lucky ANU gives students $44 free printing credit per sem (: {FLAG1}", "$")
DAEMON_RED = Drink("Red Daemon", 3.40, "monstrous caffeine to make u red in the eyes", "R")
DAEMON_PINK = Drink("Pink Daemon", 3.60, "somehow with more red 40 than the red one", "P")
DAEMON_GREY = Drink("Grey Daemon", 3.60, "only <insert demographic> drink these smh", "G")
DAEMON_ROSE_GOLD = Drink("Rose Gold Daemon", 8.80, f"uhh... i suppose it's different :/ {FLAG2}", "X")
DAEMONS = [DAEMON_RED, DAEMON_PINK, DAEMON_GREY, DAEMON_ROSE_GOLD]
randaemon = lambda: DAEMONS[choice(range(0,3))]

MYSTERY = Drink("Mystery Drink", 2.00, "grab a real mystery drink from our vendo in Skaidrite Darius!", "?")
BUZZFIZZ = Drink("BuzzFizz", 2.00, "i think i screwed up the interview ;/", "B")
FLAGSHIP = Drink("CSSodA", 0.00, f"only the best for our best :D . {FLAG3}", "*")


class Virtuaroyd:
    """
    The `Virtuaroyd` vending machine! 
    """
    def __init__(self):
        print(TEXTS["welcome"])

        self.rng = randint(0,1<<64 - 1) # random 64-bit integer
        self.shuffle()
        self.key = str(self.rng)

        self.drinks = [
            WATER, WATER, WATER, ELECTRON,
            WATER, SPONSODA, ELECTRON, ELECTRON,
            WATER, SPONSODA, INK, MYSTERY,
            randaemon(), randaemon(), randaemon(), randaemon(), # our stock changes every instance!
            EMPTY, DAEMON_ROSE_GOLD, EMPTY, EMPTY               # inaccessible, we used to sell rose gold tho. i miss it ;/
        ]
        self.counts = [
            0, 0, 0, 0,
            0, 0, 0, 0,
            0, 0, 0, 0,
            0, 0, 0, 0,
            0, 0, 0, 0,
        ]
        self.fill_drinks()

        self.balance = 0
        self.is_locked = True
        self.coins = {c: 0 for c in ["10c", "20c", "50c", "$1", "$2"]}


    def shuffle(self):
        vs = [15, 13, 28]
        qq = (1 << 64) - 1 
        for i in range(len(vs)):
            if i % 2:
                self.rng ^= self.rng >> vs[i]
            else:
                self.rng ^= (self.rng << vs[i]) & qq

    def fill_drinks(self):
        v = self.rng
        for r in range(4):
            for c in range(4):
                i = 4*r + c
                self.counts[i] += v % 16
                v >>= 4

    def show(self):
        f = lambda i: f"{self.drinks[i].icon} ({hex(self.counts[i])})"
        d = lambda dr: f"{dr.icon}: {dr.name} - ${dr.price:.2f}"
        text = f"""
        1        2        3        4
    A   {f(0)}  {f(1)}  {f(2)}  {f(3)}        {d(WATER)}
                                                  {d(ELECTRON)}
    B   {f(4)}  {f(5)}  {f(6)}  {f(7)}        {d(SPONSODA)}
                                                  {d(INK)}
    C   {f(8)}  {f(9)}  {f(10)}  {f(11)}        {d(DAEMON_RED)}
                                                  {d(DAEMON_PINK)}
    D   {f(12)}  {f(13)}  {f(14)}  {f(15)}        {d(DAEMON_GREY)}
                                                  {d(MYSTERY)}

    Current balance: ${self.balance:.2f}
    """
        print(text)

    def insert(self, c: str):
        if c not in ["10c", "20c", "50c", "$1", "$2"]:
            print(TEXTS["insert-fail"].format(coin=c))
            return
        if c == "10c":
            self.balance += 0.10
        elif c == "20c":
            self.balance += 0.20
        elif c == "50c":
            self.balance += 0.50
        elif c == "$1":
            self.balance += 1
        elif c == "$2":
            self.balance += 2

        self.coins[c] += 1
        self.balance = round(100 * self.balance) / 100 # rounding issues
        print(TEXTS["insert-good"].format(coin=c, bal=self.balance))

    def rc_to_ind(self, r: str, c: str) -> int | None:
        if len(r) != 1 or len(c) != 1:
            return None
        c_int = None
        try:
            c_int = int(c) - 1
        except:
            return None
        r_int = ord(r) - ord('A')
        
        i = 4*r_int + c_int
        if i >> 0 and i < 16:
            return i
        return None

    def _buy_mystery(self) -> Drink:
        for _ in range(26):
            self.shuffle()
        if self.rng == 67_83_83_65_2026: # u got this
            return FLAGSHIP
        
        v = self.rng / (1 << 64)
        if 0 <= v and v < 1/7:
            return WATER
        if 1/7 <= v and v < 2/7:
            return ELECTRON
        if 2/7 <= v and v < 3/7:
            return SPONSODA
        if 3/7 <= v and v < 4/7:
            return DAEMON_RED
        if 4/7 <= v and v < 5/7:
            return DAEMON_PINK
        if 5/7 <= v and v < 6/7:
            return DAEMON_GREY
        if 6/7 <= v and v <= 1:
            return BUZZFIZZ
        
        return EMPTY # failsafe


    def buy(self, r: str, c: str):
        i = self.rc_to_ind(r,c)
        if i is None:
            print(TEXTS["buy-fail-fmt"].format(row=r,col=c))
            return
        drink = self.drinks[i]
        if self.counts[i] <= 0:
            print(TEXTS["buy-fail-stk"].format(drink=drink.name,row=r,col=c))
            return
        if self.balance < drink.price:
            print(TEXTS["buy-fail-bal"].format(bal=self.balance,drink=drink.name))
            return
        
        # success
        self.counts[i] -= 1
        self.balance -= drink.price
        if drink.name == "Mystery Drink":
            print("mystery time !!")
            drink = self._buy_mystery()
        print("~whirr~")
        sleep(1)
        print("*clink!*")
        sleep(0.75)
        print(TEXTS["buy-good"].format(drink=drink.name,bal=self.balance,desc=drink.desc))

    def unlock(self, key: str):
        if not self.is_locked:
            print(TEXTS["unlock-fail-lck"])
            return
        if key != self.key:
            print(TEXTS["unlock-fail-key"].format(key=key))
            return
        print(TEXTS["unlock-good"])
        self.is_locked = False

    def cointray(self):
        if self.is_locked:
            print(TEXTS["cointray-fail"])
            return
        text = "Cointray: \n"
        for k,v in self.coins.items():
            text += f"{k:5s} : {v}\n"
        print(text)

    def refill(self, r: str, c: str):
        if self.is_locked:
            print(TEXTS["refill-fail-lck"])
            return
        i = self.rc_to_ind(r,c)
        if i is None:
            print(TEXTS["refill-fail-fmt"].format(row=r,col=c))
            return
        if self.counts[i] >= 15:
            print(TEXTS["refill-fail-amt"].format(row=r,col=c))
            return
        
        self.counts[i] += 1
        print(TEXTS["refill-good"].format(drink=self.drinks[i].name,row=r,col=c,cnt=self.counts[i]))

    def shake(self, s: str):
        if s.isdigit():
            v = int(s) & ((1 << 64) - 1)
            self.rng ^= v

            print("* ccrmm *")
            sleep(0.5)
            print("# ccrackk #")
            sleep(0.9)
        msgs = [
            "... dont do that plz -_-",
            "no drinks for u ! -V-",
            "why u do dat ;-;",
            "oww (@ W @) *dizzy spinning noises*"
        ]
        print(msgs[self.rng % 4])
        pass
        


def main():
    virtuaroyd = Virtuaroyd()

    usr = []
    while True:
        usr = input(f"virtuaroyd ({'L' if virtuaroyd.is_locked else 'U'}) > ").split()
        if not usr:
            continue
        if usr[0] == "help":
            print(TEXTS["help"])

        elif usr[0] == "insert":
            if len(usr) != 2:
                print(TEXTS["bad-fmt"])
                continue
            virtuaroyd.insert(usr[1])

        elif usr[0] == "show":
            virtuaroyd.show()

        elif usr[0] == "buy":
            if len(usr) != 3:
                print(TEXTS["bad-fmt"])
                continue
            virtuaroyd.buy(usr[1], usr[2])

        elif usr[0] == "unlock":
            if len(usr) != 2:
                print(TEXTS["bad-fmt"])
                continue
            virtuaroyd.unlock(usr[1])
        elif usr[0] == "cointray":
            virtuaroyd.cointray()
        elif usr[0] == "refill":
            if len(usr) != 3:
                print(TEXTS["bad-fmt"])
                continue
            virtuaroyd.refill(usr[1],usr[2])
        elif usr[0] == "shake":
            v = ""
            if len(usr) >= 2:
                v = usr[1]
            virtuaroyd.shake(v)
        
        elif usr[0] == "exit":
            print(TEXTS["exit"])
            break

        else:
            print(TEXTS["bad-fmt"])
        

if __name__ == "__main__":
    main()
