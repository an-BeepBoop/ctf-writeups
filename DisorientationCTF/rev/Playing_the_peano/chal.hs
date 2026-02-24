{-# LANGUAGE AllowAmbiguousTypes #-}
{-# LANGUAGE DataKinds #-}
{-# LANGUAGE GADTs #-}
{-# LANGUAGE TypeFamilies #-}
{-# LANGUAGE UndecidableInstances #-}

data A = B | S A

type family K (x :: A) (y :: A) :: A where
  K 'B y = y
  K ('S x) y = 'S (K x y)

type family M (x :: A) (y :: A) :: A where
  M 'B y = B
  M x 'B = B
  M ('S x) y = K y (M x y)

type family R (x :: A) (y :: A) :: A where
  R x 'B = S B
  R x ('S y) = M x (R x y)

type family P (x :: A) :: A where
  P 'B = B
  P ('S x) = K (P x) ('S x)

class D (n :: A) where
  d :: Int

instance D 'B where
  d = 0

instance (D n) => D ('S n) where
  d = 1 + d @n

main :: IO ()
main = do
  let number = d @(K (P (P (P (R ('S ('S 'B)) ('S ('S ('S ('S B)))))))) ('S ('S B)))
  let output = "The flag is disorientation{" ++ show number ++ "}"
  putStrLn output
  return ()
