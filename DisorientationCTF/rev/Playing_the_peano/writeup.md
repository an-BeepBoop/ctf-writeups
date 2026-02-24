# Playing the peano

Some context from [Peano numbers](https://wiki.haskell.org/Peano_numbers) 

>Peano numbers are a simple way of representing the natural numbers using only a zero value and a successor function. In Haskell it is easy to create a type of Peano number values, but since unary representation is inefficient, they are more often used to do type arithmetic due to their simplicity. 

## Peano number values

```hs
 data Peano = Zero | Succ Peano
```

Here Zero and Succ are values (constructors). Zero has type Peano, and Succ has type Peano -> Peano. The natural number zero is represented by Zero, one by Succ Zero, two by Succ (Succ Zero) and so forth.

```hs
add Zero b = b
add (Succ a) b = Succ (add a b)
```

With this in mind clearly our `chal.hs` is an implementation of **Peano number**, lets analyse what each function does.

```hs
-- Is clearly the Peano number type
data A = B | S A

-- Is addition
-- Base case: 0 + y = y
-- Recursive case: (x+1) + y = 1 + (x + y)
type family K (x :: A) (y :: A) :: A where
    K    'B y = y
    K    ('S x) y = 'S (K x y)

-- Is multiplication
-- Base case: 0 * y = 0, x * 0 = 0
-- Recursive case: (x+1) * y = y + (x * y)
type family M (x :: A) (y :: A) :: A where
    M    'B y = B
    M    x 'B = B
    M    ('S x) y = K y (M x y)

-- Is exponentiation
-- Base case: x^0 = 1
-- Recursive case: x^(y+1) = x * (x^y)
type family R (x :: A) (y :: A) :: A where
    R   x 'B = S B
    R   x ('S y) = M x (R x y)

-- Sum of first n numbers (triangular numbers)
-- Base case: sum of 0 numbers = 0
-- Recursive case: sum of first (n+1) numbers = sum of first n numbers + (n+1)
type family P (x :: A) :: A where
    P              'B = B
    P              ('S x) = K (P x) ('S x)

-- Type class to convert Peano numbers to runtime integers
class D (n :: A) where
  d :: Int

-- Base case: 0 maps to 0
instance D 'B where
  d = 0

-- Recursive case: (n+1) maps to 1 + d n
instance (D n) => D ('S n) where
  d = 1 + d @n
```

With all the helpers examined, let’s look at `main`. Our `main` function effectively **computes a type-level number using Peano arithmetic and converts it to a runtime `Int`**, which is then inserted into the flag. Let's look at the operations it does to recover the flag.

```hs
let number = d @(K (P (P (P (R ('S ('S 'B)) ('S ('S ('S ('S B)))))))) ('S ('S B)))
```

* `'S ('S 'B)` represents 2, and `'S ('S ('S ('S B)))` represents 4.

  * $R(2,4) = 2^4 = 16$

* $P(16)$ computes the sum of the first 16 numbers: $\frac{16 \cdot 17}{2}  = 136$
  * $P(P(16)) = P(136) = \frac{136 \cdot 137}{2} = 9316$
  * $P(P(P(16))) = P(9316) = \frac{9316 \cdot 9317}{2} = 43{,}398{,}586$

* $K(P(P(P(16))), 2) = 43{,}398{,}586 + 2 = 43{,}398{,}588$

Finally, the `d` function converts this type-level Peano number to a runtime integer. This is the number that is inserted into our flag:

```
disorientation{43398588}
```

