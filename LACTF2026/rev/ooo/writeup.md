# ooo

Starting from the provided `ooo.py`, we can use `LSP NvRenamer (or a similar tool) to rename the 
obfuscated identifiers into something more readable. After doing so, we obtain the translated version ![translated.py](./translated.py)

Next, by inlining function calls the program can be simplified to the following:
```python
eacrypted_flag = [205, 196, 215, 218, 225, 226, 1189, 2045, 2372, 9300, 8304, 660, 8243, 16057, 16113, 16057, 16004, 16007, 16006, 8561, 805, 346, 195, 201, 154, 146, 223]

guess = input("What's the flag? ") # remember, flags start with lactf{

if (len(guess) < len(encrypted_flag)):
    print("That's too short :(")
    exit()
    
for i in range(len(encrypted_flag)-1):
    j = ord(guess[i])
    k = ord(guess[i+1])
    if ((j + k) != encrypted_flag[i ^ (j * k) % j]):
        print("That's not the flag :(")
        exit()
    
print("That's the flag! :)")
```

From this code, we can derive the following equation, where $x_i$ represents the ASCII value of 
the $i$'th character of our guess (the flag), and where $y$ is the `encrypted_flag` array:

$$
x_i + x_{i+1} = y\left[i \oplus \left((x_i \cdot x_{i+1}) \bmod x_i\right)\right]
$$

Since
$$
(x_i \cdot x_{i+1}) \bmod x_i = 0 \quad \text{(for } x_i \neq 0\text{)},
$$
the index expression simplifies to:
$$
i \oplus 0 = i
$$

This reduces the equation to the much simpler form:
$$
x_i + x_{i+1} = y_i
$$

or equivalently,

$$
x_{i+1} = y_i - x_i \\
$$

This gives a linear recurrence relation. Because the flag is known to start with `lactf{`, we have the first initial values. With this initial value, we can directly compute the remaining characters 
and recover the flag.

```
./solve.py 
lactf{gоοօỏơóὀόὸὁὃὄὂȯöd_j0b}
```
