
lines = [
    "W F E A F Q M C S H T F M M A K",
    "C Q B H T T N A A Q B C Q A A S",
    "J C P P T V D A F U I L A Q T H",
    "S J A H N V P P E A A T C Q T A",
    "Q Q K I N A N V Q Q V Q A I E V",
    "T T V W D V T H I C P L C Q B V",
    "A T V Q L J A J C P P J C Q Q H"
]

with open("encrypted.txt", "w") as f:
    for line in lines:
        # make sure there are exactly 16 letters separated by a single space
        letters = line.split()
        if len(letters) != 16:
            raise ValueError("Line does not have 16 letters: " + line)
        f.write(" ".join(letters) + "\n")
