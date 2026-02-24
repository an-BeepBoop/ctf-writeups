trait CA {}
struct Op2<A,B>(A, B);
trait CB {}
trait CE {}
struct Zero;
impl CA for Zero {}
struct One;
struct Two;
struct Three;
impl CA for Three {}
struct Four;
struct Five;
struct Six;
impl CA for Six {}
struct Seven;
struct Eight;
struct Nine;
impl CA for Nine {}
struct Ten;
impl CE for Op2<Zero, Zero> {}
impl CE for Op2<One, One> {}
impl CE for Op2<Two, Two> {}
impl CE for Op2<Three, Three> {}
impl CE for Op2<Four, Four> {}
impl CB for Op2<Zero, One> {}
impl CB for Op2<Zero, Two> {}
impl CB for Op2<Zero, Three> {}
impl CB for Op2<Zero, Four> {}
impl CB for Op2<Zero, Five> {}
impl CB for Op2<Zero, Six> {}
impl CB for Op2<Zero, Seven> {}
impl CB for Op2<Zero, Eight> {}
impl CB for Op2<Zero, Nine> {}
impl CB for Op2<Zero, Ten> {}
impl CB for Op2<One, Two> {}
impl CB for Op2<One, Three> {}
impl CB for Op2<One, Four> {}
impl CB for Op2<One, Five> {}
impl CB for Op2<One, Six> {}
impl CB for Op2<One, Seven> {}
impl CB for Op2<One, Eight> {}
impl CB for Op2<One, Nine> {}
impl CB for Op2<One, Ten> {}
impl CB for Op2<Two, Three> {}
impl CB for Op2<Two, Four> {}
impl CB for Op2<Two, Five> {}
impl CB for Op2<Two, Six> {}
impl CB for Op2<Two, Seven> {}
impl CB for Op2<Two, Eight> {}
impl CB for Op2<Two, Nine> {}
impl CB for Op2<Two, Ten> {}
impl CB for Op2<Three, Four> {}
impl CB for Op2<Three, Five> {}
impl CB for Op2<Three, Six> {}
impl CB for Op2<Three, Seven> {}
impl CB for Op2<Three, Eight> {}
impl CB for Op2<Three, Nine> {}
impl CB for Op2<Three, Ten> {}
impl CB for Op2<Four, Five> {}
impl CB for Op2<Four, Six> {}
impl CB for Op2<Four, Seven> {}
impl CB for Op2<Four, Eight> {}
impl CB for Op2<Four, Nine> {}
impl CB for Op2<Four, Ten> {}
impl CB for Op2<Five, Six> {}
impl CB for Op2<Five, Seven> {}
impl CB for Op2<Five, Eight> {}
impl CB for Op2<Five, Nine> {}
impl CB for Op2<Five, Ten> {}
impl CB for Op2<Six, Seven> {}
impl CB for Op2<Six, Eight> {}
impl CB for Op2<Six, Nine> {}
impl CB for Op2<Six, Ten> {}
impl CB for Op2<Seven, Eight> {}
impl CB for Op2<Seven, Nine> {}
impl CB for Op2<Seven, Ten> {}
impl CB for Op2<Eight, Nine> {}
impl CB for Op2<Eight, Ten> {}
impl CB for Op2<Nine, Ten> {}
impl CE for Op2<Zero, One> {}
impl CE for Op2<Zero, Two> {}
impl CE for Op2<Zero, Three> {}
impl CE for Op2<Zero, Four> {}
impl CE for Op2<Zero, Five> {}
impl CE for Op2<Zero, Six> {}
impl CE for Op2<Zero, Seven> {}
impl CE for Op2<Zero, Eight> {}
impl CE for Op2<Zero, Nine> {}
impl CE for Op2<One, Zero> {}
impl CE for Op2<One, Two> {}
impl CE for Op2<One, Three> {}
impl CE for Op2<One, Four> {}
impl CE for Op2<One, Five> {}
impl CE for Op2<One, Six> {}
impl CE for Op2<One, Seven> {}
impl CE for Op2<One, Eight> {}
impl CE for Op2<Two, Zero> {}
impl CE for Op2<Two, One> {}
impl CE for Op2<Two, Three> {}
impl CE for Op2<Two, Four> {}
impl CE for Op2<Two, Five> {}
impl CE for Op2<Two, Six> {}
impl CE for Op2<Two, Seven> {}
impl CE for Op2<Three, Zero> {}
impl CE for Op2<Three, One> {}
impl CE for Op2<Three, Two> {}
impl CE for Op2<Three, Four> {}
impl CE for Op2<Three, Five> {}
impl CE for Op2<Three, Six> {}
impl CE for Op2<Four, Zero> {}
impl CE for Op2<Four, One> {}
impl CE for Op2<Four, Two> {}
impl CE for Op2<Four, Three> {}
impl CE for Op2<Four, Five> {}
impl CE for Op2<Five, Zero> {}
impl CE for Op2<Five, One> {}
impl CE for Op2<Five, Two> {}
impl CE for Op2<Five, Three> {}
impl CE for Op2<Five, Four> {}
impl CE for Op2<Six, Zero> {}
impl CE for Op2<Six, One> {}
impl CE for Op2<Six, Two> {}
impl CE for Op2<Six, Three> {}
impl CE for Op2<Seven, Zero> {}
impl CE for Op2<Seven, One> {}
impl CE for Op2<Seven, Two> {}
impl CE for Op2<Eight, Zero> {}
impl CE for Op2<Eight, One> {}
impl CE for Op2<Nine, Zero> {}
struct Op3<A,B,C>(A, B, C);
trait CC {}
trait CD {}
impl CC for Op3<Zero, Zero, Zero> {}
impl CC for Op3<Zero, One, One> {}
impl CC for Op3<Zero, Two, Two> {}
impl CC for Op3<Zero, Three, Three> {}
impl CC for Op3<Zero, Four, Four> {}
impl CC for Op3<Zero, Five, Five> {}
impl CC for Op3<Zero, Six, Six> {}
impl CC for Op3<Zero, Seven, Seven> {}
impl CC for Op3<Zero, Eight, Eight> {}
impl CC for Op3<Zero, Nine, Nine> {}
impl CC for Op3<Zero, Ten, Ten> {}
impl CD for Op3<One, Zero, Zero> {}
impl CC for Op3<One, Zero, One> {}
impl CC for Op3<One, One, Two> {}
impl CC for Op3<One, Two, Three> {}
impl CC for Op3<One, Three, Four> {}
impl CC for Op3<One, Four, Five> {}
impl CC for Op3<One, Five, Six> {}
impl CC for Op3<One, Six, Seven> {}
impl CC for Op3<One, Seven, Eight> {}
impl CC for Op3<One, Eight, Nine> {}
impl CC for Op3<One, Nine, Ten> {}
impl CD for Op3<Two, Zero, Zero> {}
impl CD for Op3<Two, Zero, One> {}
impl CC for Op3<Two, Zero, Two> {}
impl CD for Op3<Two, One, Zero> {}
impl CC for Op3<Two, One, Three> {}
impl CC for Op3<Two, Two, Four> {}
impl CC for Op3<Two, Three, Five> {}
impl CC for Op3<Two, Four, Six> {}
impl CC for Op3<Two, Five, Seven> {}
impl CC for Op3<Two, Six, Eight> {}
impl CC for Op3<Two, Seven, Nine> {}
impl CC for Op3<Two, Eight, Ten> {}
impl CD for Op3<Three, Zero, Zero> {}
impl CD for Op3<Three, Zero, One> {}
impl CD for Op3<Three, Zero, Two> {}
impl CC for Op3<Three, Zero, Three> {}
impl CD for Op3<Three, One, Zero> {}
impl CD for Op3<Three, One, One> {}
impl CC for Op3<Three, One, Four> {}
impl CD for Op3<Three, Two, Zero> {}
impl CC for Op3<Three, Two, Five> {}
impl CC for Op3<Three, Three, Six> {}
impl CC for Op3<Three, Four, Seven> {}
impl CC for Op3<Three, Five, Eight> {}
impl CC for Op3<Three, Six, Nine> {}
impl CC for Op3<Three, Seven, Ten> {}
impl CD for Op3<Four, Zero, Zero> {}
impl CD for Op3<Four, Zero, One> {}
impl CD for Op3<Four, Zero, Two> {}
impl CD for Op3<Four, Zero, Three> {}
impl CC for Op3<Four, Zero, Four> {}
impl CD for Op3<Four, One, Zero> {}
impl CD for Op3<Four, One, One> {}
impl CD for Op3<Four, One, Two> {}
impl CC for Op3<Four, One, Five> {}
impl CD for Op3<Four, Two, Zero> {}
impl CD for Op3<Four, Two, One> {}
impl CC for Op3<Four, Two, Six> {}
impl CD for Op3<Four, Three, Zero> {}
impl CC for Op3<Four, Three, Seven> {}
impl CC for Op3<Four, Four, Eight> {}
impl CC for Op3<Four, Five, Nine> {}
impl CC for Op3<Four, Six, Ten> {}
impl CD for Op3<Five, Zero, Zero> {}
impl CD for Op3<Five, Zero, One> {}
impl CD for Op3<Five, Zero, Two> {}
impl CD for Op3<Five, Zero, Three> {}
impl CD for Op3<Five, Zero, Four> {}
impl CC for Op3<Five, Zero, Five> {}
impl CD for Op3<Five, One, Zero> {}
impl CD for Op3<Five, One, One> {}
impl CD for Op3<Five, One, Two> {}
impl CD for Op3<Five, One, Three> {}
impl CC for Op3<Five, One, Six> {}
impl CD for Op3<Five, Two, Zero> {}
impl CD for Op3<Five, Two, One> {}
impl CD for Op3<Five, Two, Two> {}
impl CC for Op3<Five, Two, Seven> {}
impl CD for Op3<Five, Three, Zero> {}
impl CD for Op3<Five, Three, One> {}
impl CC for Op3<Five, Three, Eight> {}
impl CD for Op3<Five, Four, Zero> {}
impl CC for Op3<Five, Four, Nine> {}
impl CC for Op3<Five, Five, Ten> {}
impl CD for Op3<Six, Zero, Zero> {}
impl CD for Op3<Six, Zero, One> {}
impl CD for Op3<Six, Zero, Two> {}
impl CD for Op3<Six, Zero, Three> {}
impl CD for Op3<Six, Zero, Four> {}
impl CD for Op3<Six, Zero, Five> {}
impl CC for Op3<Six, Zero, Six> {}
impl CD for Op3<Six, One, Zero> {}
impl CD for Op3<Six, One, One> {}
impl CD for Op3<Six, One, Two> {}
impl CD for Op3<Six, One, Three> {}
impl CD for Op3<Six, One, Four> {}
impl CC for Op3<Six, One, Seven> {}
impl CD for Op3<Six, Two, Zero> {}
impl CD for Op3<Six, Two, One> {}
impl CD for Op3<Six, Two, Two> {}
impl CD for Op3<Six, Two, Three> {}
impl CC for Op3<Six, Two, Eight> {}
impl CD for Op3<Six, Three, Zero> {}
impl CD for Op3<Six, Three, One> {}
impl CD for Op3<Six, Three, Two> {}
impl CC for Op3<Six, Three, Nine> {}
impl CD for Op3<Six, Four, Zero> {}
impl CD for Op3<Six, Four, One> {}
impl CC for Op3<Six, Four, Ten> {}
impl CD for Op3<Six, Five, Zero> {}
impl CD for Op3<Seven, Zero, Zero> {}
impl CD for Op3<Seven, Zero, One> {}
impl CD for Op3<Seven, Zero, Two> {}
impl CD for Op3<Seven, Zero, Three> {}
impl CD for Op3<Seven, Zero, Four> {}
impl CD for Op3<Seven, Zero, Five> {}
impl CD for Op3<Seven, Zero, Six> {}
impl CC for Op3<Seven, Zero, Seven> {}
impl CD for Op3<Seven, One, Zero> {}
impl CD for Op3<Seven, One, One> {}
impl CD for Op3<Seven, One, Two> {}
impl CD for Op3<Seven, One, Three> {}
impl CD for Op3<Seven, One, Four> {}
impl CD for Op3<Seven, One, Five> {}
impl CC for Op3<Seven, One, Eight> {}
impl CD for Op3<Seven, Two, Zero> {}
impl CD for Op3<Seven, Two, One> {}
impl CD for Op3<Seven, Two, Two> {}
impl CD for Op3<Seven, Two, Three> {}
impl CD for Op3<Seven, Two, Four> {}
impl CC for Op3<Seven, Two, Nine> {}
impl CD for Op3<Seven, Three, Zero> {}
impl CD for Op3<Seven, Three, One> {}
impl CD for Op3<Seven, Three, Two> {}
impl CD for Op3<Seven, Three, Three> {}
impl CC for Op3<Seven, Three, Ten> {}
impl CD for Op3<Seven, Four, Zero> {}
impl CD for Op3<Seven, Four, One> {}
impl CD for Op3<Seven, Four, Two> {}
impl CD for Op3<Seven, Five, Zero> {}
impl CD for Op3<Seven, Five, One> {}
impl CD for Op3<Seven, Six, Zero> {}
impl CD for Op3<Eight, Zero, Zero> {}
impl CD for Op3<Eight, Zero, One> {}
impl CD for Op3<Eight, Zero, Two> {}
impl CD for Op3<Eight, Zero, Three> {}
impl CD for Op3<Eight, Zero, Four> {}
impl CD for Op3<Eight, Zero, Five> {}
impl CD for Op3<Eight, Zero, Six> {}
impl CD for Op3<Eight, Zero, Seven> {}
impl CC for Op3<Eight, Zero, Eight> {}
impl CD for Op3<Eight, One, Zero> {}
impl CD for Op3<Eight, One, One> {}
impl CD for Op3<Eight, One, Two> {}
impl CD for Op3<Eight, One, Three> {}
impl CD for Op3<Eight, One, Four> {}
impl CD for Op3<Eight, One, Five> {}
impl CD for Op3<Eight, One, Six> {}
impl CC for Op3<Eight, One, Nine> {}
impl CD for Op3<Eight, Two, Zero> {}
impl CD for Op3<Eight, Two, One> {}
impl CD for Op3<Eight, Two, Two> {}
impl CD for Op3<Eight, Two, Three> {}
impl CD for Op3<Eight, Two, Four> {}
impl CD for Op3<Eight, Two, Five> {}
impl CC for Op3<Eight, Two, Ten> {}
impl CD for Op3<Eight, Three, Zero> {}
impl CD for Op3<Eight, Three, One> {}
impl CD for Op3<Eight, Three, Two> {}
impl CD for Op3<Eight, Three, Three> {}
impl CD for Op3<Eight, Three, Four> {}
impl CD for Op3<Eight, Four, Zero> {}
impl CD for Op3<Eight, Four, One> {}
impl CD for Op3<Eight, Four, Two> {}
impl CD for Op3<Eight, Four, Three> {}
impl CD for Op3<Eight, Five, Zero> {}
impl CD for Op3<Eight, Five, One> {}
impl CD for Op3<Eight, Five, Two> {}
impl CD for Op3<Eight, Six, Zero> {}
impl CD for Op3<Eight, Six, One> {}
impl CD for Op3<Eight, Seven, Zero> {}
impl CD for Op3<Nine, Zero, Zero> {}
impl CD for Op3<Nine, Zero, One> {}
impl CD for Op3<Nine, Zero, Two> {}
impl CD for Op3<Nine, Zero, Three> {}
impl CD for Op3<Nine, Zero, Four> {}
impl CD for Op3<Nine, Zero, Five> {}
impl CD for Op3<Nine, Zero, Six> {}
impl CD for Op3<Nine, Zero, Seven> {}
impl CD for Op3<Nine, Zero, Eight> {}
impl CC for Op3<Nine, Zero, Nine> {}
impl CD for Op3<Nine, One, Zero> {}
impl CD for Op3<Nine, One, One> {}
impl CD for Op3<Nine, One, Two> {}
impl CD for Op3<Nine, One, Three> {}
impl CD for Op3<Nine, One, Four> {}
impl CD for Op3<Nine, One, Five> {}
impl CD for Op3<Nine, One, Six> {}
impl CD for Op3<Nine, One, Seven> {}
impl CC for Op3<Nine, One, Ten> {}
impl CD for Op3<Nine, Two, Zero> {}
impl CD for Op3<Nine, Two, One> {}
impl CD for Op3<Nine, Two, Two> {}
impl CD for Op3<Nine, Two, Three> {}
impl CD for Op3<Nine, Two, Four> {}
impl CD for Op3<Nine, Two, Five> {}
impl CD for Op3<Nine, Two, Six> {}
impl CD for Op3<Nine, Three, Zero> {}
impl CD for Op3<Nine, Three, One> {}
impl CD for Op3<Nine, Three, Two> {}
impl CD for Op3<Nine, Three, Three> {}
impl CD for Op3<Nine, Three, Four> {}
impl CD for Op3<Nine, Three, Five> {}
impl CD for Op3<Nine, Four, Zero> {}
impl CD for Op3<Nine, Four, One> {}
impl CD for Op3<Nine, Four, Two> {}
impl CD for Op3<Nine, Four, Three> {}
impl CD for Op3<Nine, Four, Four> {}
impl CD for Op3<Nine, Five, Zero> {}
impl CD for Op3<Nine, Five, One> {}
impl CD for Op3<Nine, Five, Two> {}
impl CD for Op3<Nine, Five, Three> {}
impl CD for Op3<Nine, Six, Zero> {}
impl CD for Op3<Nine, Six, One> {}
impl CD for Op3<Nine, Six, Two> {}
impl CD for Op3<Nine, Seven, Zero> {}
impl CD for Op3<Nine, Seven, One> {}
impl CD for Op3<Nine, Eight, Zero> {}
impl CD for Op3<Ten, Zero, Zero> {}
impl CD for Op3<Ten, Zero, One> {}
impl CD for Op3<Ten, Zero, Two> {}
impl CD for Op3<Ten, Zero, Three> {}
impl CD for Op3<Ten, Zero, Four> {}
impl CD for Op3<Ten, Zero, Five> {}
impl CD for Op3<Ten, Zero, Six> {}
impl CD for Op3<Ten, Zero, Seven> {}
impl CD for Op3<Ten, Zero, Eight> {}
impl CD for Op3<Ten, Zero, Nine> {}
impl CC for Op3<Ten, Zero, Ten> {}
impl CD for Op3<Ten, One, Zero> {}
impl CD for Op3<Ten, One, One> {}
impl CD for Op3<Ten, One, Two> {}
impl CD for Op3<Ten, One, Three> {}
impl CD for Op3<Ten, One, Four> {}
impl CD for Op3<Ten, One, Five> {}
impl CD for Op3<Ten, One, Six> {}
impl CD for Op3<Ten, One, Seven> {}
impl CD for Op3<Ten, One, Eight> {}
impl CD for Op3<Ten, Two, Zero> {}
impl CD for Op3<Ten, Two, One> {}
impl CD for Op3<Ten, Two, Two> {}
impl CD for Op3<Ten, Two, Three> {}
impl CD for Op3<Ten, Two, Four> {}
impl CD for Op3<Ten, Two, Five> {}
impl CD for Op3<Ten, Two, Six> {}
impl CD for Op3<Ten, Two, Seven> {}
impl CD for Op3<Ten, Three, Zero> {}
impl CD for Op3<Ten, Three, One> {}
impl CD for Op3<Ten, Three, Two> {}
impl CD for Op3<Ten, Three, Three> {}
impl CD for Op3<Ten, Three, Four> {}
impl CD for Op3<Ten, Three, Five> {}
impl CD for Op3<Ten, Three, Six> {}
impl CD for Op3<Ten, Four, Zero> {}
impl CD for Op3<Ten, Four, One> {}
impl CD for Op3<Ten, Four, Two> {}
impl CD for Op3<Ten, Four, Three> {}
impl CD for Op3<Ten, Four, Four> {}
impl CD for Op3<Ten, Four, Five> {}
impl CD for Op3<Ten, Five, Zero> {}
impl CD for Op3<Ten, Five, One> {}
impl CD for Op3<Ten, Five, Two> {}
impl CD for Op3<Ten, Five, Three> {}
impl CD for Op3<Ten, Five, Four> {}
impl CD for Op3<Ten, Six, Zero> {}
impl CD for Op3<Ten, Six, One> {}
impl CD for Op3<Ten, Six, Two> {}
impl CD for Op3<Ten, Six, Three> {}
impl CD for Op3<Ten, Seven, Zero> {}
impl CD for Op3<Ten, Seven, One> {}
impl CD for Op3<Ten, Seven, Two> {}
impl CD for Op3<Ten, Eight, Zero> {}
impl CD for Op3<Ten, Eight, One> {}
impl CD for Op3<Ten, Nine, Zero> {}
use std::marker::PhantomData;
struct Question<A, B, C, D, E, F, G, H, I, J, K, L, M, N, O, P, Q, R, S, T, U, V, W, X, Y, Z>(PhantomData<(A, B, C, D, E, F, G, H, I, J, K, L, M, N, O, P, Q, R, S, T, U, V, W, X, Y, Z)>);

impl<A, B, C, D, E, F, G, H, I, J, K, L, M, N, O, P, Q, R, S, T, U, V, W, X, Y, Z> Question<A, B, C, D, E, F, G, H, I, J, K, L, M, N, O, P, Q, R, S, T, U, V, W, X, Y, Z> where
Op3<D, J, K>: CD, 
Op3<C, E, Q>: CD, 
Op2<X, S>: CE, 
Op2<Y, W>: CE, 
Op2<W, G>: CE, 
Op3<C, E, G>: CD, 
Op3<B, M, Q>: CD, 
Op2<T, E>: CE, 
Op3<C, I, X>: CD, 
Op3<Q, S, X>: CC, 
Op3<N, O, X>: CD, 
Op3<E, K, O>: CC, 
Op2<H, S>: CE, 
Op3<C, E, M>: CD, 
Op3<C, K, Y>: CD, 
Op2<A, B>: CB, 
Op3<E, J, L>: CC, 
Op3<P, S, Y>: CD, 
N: CA, 
Op3<C, E, I>: CD, 
Op3<D, Q, S>: CD, 
Op2<J, D>: CE, 
Op3<F, J, T>: CC, 
Op2<F, Q>: CE, 
Op3<B, E, W>: CD, 
Op3<N, U, W>: CD, 
Op2<L, T>: CE, 
Op3<G, Q, U>: CD, 
Op3<C, F, U>: CD, 
Op2<S, I>: CE, 
Op3<F, J, U>: CD, 
Op2<O, P>: CB, 
Op3<H, Q, U>: CD, 
L: CA, 
Op2<X, I>: CE, 
Op3<C, H, J>: CD, 
Op3<C, U, Y>: CD, 
Op3<V, W, Y>: CC, 
Op3<G, J, Z>: CC, 
Op3<B, I, Q>: CD, 
Op3<C, Q, W>: CD, 
Op3<C, J, T>: CD, 
Op2<S, W>: CE, 
Op3<F, J, V>: CD, 
Op3<C, Q, X>: CD, 
Op3<B, S, V>: CD, 
Op3<C, G, X>: CD, 
Op2<H, J>: CE, 
Op3<L, Q, W>: CC, 
Op3<B, L, S>: CD, 
Op3<R, S, W>: CD, 
Op3<G, J, S>: CD, 
Op3<E, S, Y>: CC, 
Op3<C, L, X>: CD, 
Op2<J, S>: CE, 
Op3<R, T, V>: CD, 
Op2<G, K>: CE, 
Op2<X, E>: CE, 
Op3<D, F, P>: CC, 
Op3<N, O, U>: CD, 
Op3<D, J, X>: CD, 
Op3<C, S, W>: CD, 
Op3<C, O, V>: CD, 
Op3<F, G, R>: CC, 
Op2<Y, L>: CE, 
Op2<D, X>: CE, 
M: CA, 
Op3<C, T, V>: CD, 
Op2<O, V>: CE, 
Op3<C, F, J>: CD, 
Op3<E, J, W>: CC, 
Op3<K, W, Z>: CC, 
Op3<I, J, W>: CD, 
Op2<W, D>: CE, 
Op2<Q, S>: CE, 
Op3<P, W, Y>: CD, 
Op3<R, U, Y>: CD, 
Op3<A, Q, S>: CD, 
Op2<V, H>: CE, 
Op2<U, I>: CE, 
Op2<K, X>: CE, 
Op2<K, T>: CE, 
Op3<M, Q, Z>: CC, 
Op3<M, Q, U>: CD, 
Op3<B, L, U>: CD, 
Op2<Z, L>: CE, 
Op3<M, Q, T>: CC, 
Op2<U, H>: CE, 
Op2<A, V>: CE, 
Op3<B, H, J>: CD, 
Op2<O, E>: CE, 
Op2<X, M>: CE, 
Op3<F, H, P>: CC, 
Op3<F, J, Z>: CC, 
Op3<C, H, S>: CD, 
Op3<I, K, N>: CC, 
Op2<E, S>: CE, 
Op2<W, A>: CE, 
Op3<P, Q, W>: CD, 
Op2<L, S>: CE, 
Op2<F, K>: CE, 
Op3<R, X, Z>: CD, 
Op3<A, L, N>: CC, 
Op2<Z, K>: CE, 
Op2<K, S>: CE, 
Op2<J, L>: CE, 
Op2<X, T>: CE, 
Op2<K, G>: CE, 
Op3<H, J, U>: CD, 
Op3<G, J, Q>: CD, 
Op3<R, X, Y>: CD, 
Op3<A, K, N>: CC, 
Op3<N, Q, X>: CD, 
Op3<L, Q, V>: CD, 
Op2<W, T>: CE, 
Op2<Q, Y>: CE, 
Op2<U, V>: CE, 
Op3<F, J, X>: CD, 
Op3<C, E, Y>: CD, 
Op3<P, Q, X>: CD, 
Op2<L, M>: CE, 
Op2<J, H>: CE, 
Op3<P, S, U>: CD, 
Op3<C, X, Y>: CD, 
Op2<W, Z>: CE, 
Op3<C, J, O>: CD, 
Op2<Q, T>: CE, 
Op3<C, E, F>: CD, 
Op3<C, O, U>: CD, 
Op2<K, W>: CE, 
Op2<E, X>: CE, 
Op2<Y, V>: CE, 
Op3<P, Q, U>: CD, 
Op3<D, J, U>: CD, 
Op2<Y, U>: CE, 
Op3<P, Q, T>: CD, 
Op2<S, T>: CB, 
Op3<D, J, Q>: CD, 
Op3<E, K, Y>: CC, 
I: CA, 
Op3<D, K, Q>: CD, 
Op3<I, O, Q>: CD, 
Op2<D, S>: CE, 
Op3<P, U, X>: CD, 
Op2<E, B>: CE, 
Op3<P, X, Y>: CD, 
Op3<I, K, V>: CD, 
Op2<M, Q>: CE, 
Op2<U, O>: CE, 
Op2<L, M>: CB, 
Op3<B, Q, V>: CD, 
Op3<M, O, Q>: CD, 
Op2<O, K>: CE, 
Op3<G, Q, W>: CD, 
Op3<B, K, P>: CC, 
Op3<F, O, P>: CC, 
Op3<N, Q, U>: CD, 
Op2<T, L>: CE, 
Op2<U, D>: CE, 
Op3<B, J, L>: CD, 
Op2<I, J>: CE, 
Op3<P, W, X>: CD, 
Op3<N, Q, T>: CD, 
Op3<I, Q, T>: CC, 
Op3<C, O, S>: CD, 
Op3<S, V, Y>: CC, 
Op3<U, V, Y>: CC, 
Op3<C, I, V>: CD, 
Op2<A, K>: CE, 
Op3<B, L, R>: CC, 
Op3<O, Q, W>: CD, 
Op3<L, V, Y>: CC, 
Op2<Q, N>: CE, 
Op2<J, G>: CE, 
Op3<C, D, V>: CD, 
Op3<A, J, X>: CD, 
Op3<P, T, V>: CD, 
Op2<I, K>: CE, 
Op2<W, K>: CE, 
Op3<B, G, Q>: CD, 
Op2<Y, K>: CE, 
Op3<S, U, Z>: CC, 
Op2<U, M>: CE, 
Op3<B, Q, T>: CD, 
Op2<U, J>: CE, 
Op2<L, U>: CE, 
Op2<U, Y>: CE, 
Op3<L, S, T>: CC, 
Op3<E, J, S>: CC, 
Op2<W, O>: CE, 
Op3<G, J, L>: CD, 
Op3<F, H, R>: CC, 
Op3<I, V, X>: CD, 
Op3<B, L, P>: CC, 
Op3<D, G, R>: CC, 
Op3<C, F, Q>: CD, 
Op3<N, X, Y>: CD, 
U: CA, 
Op3<C, H, V>: CD, 
Op2<V, I>: CE, 
Op2<A, U>: CE, 
Op3<N, O, W>: CD, 
Op2<Z, E>: CE, 
Op3<A, E, U>: CD, 
Op3<H, L, Q>: CD, 
Op2<K, L>: CE, 
Op3<C, E, W>: CD, 
Op2<W, E>: CE, 
Op2<B, J>: CE, 
Op3<B, J, W>: CD, 
Op2<U, E>: CE, 
Op3<C, M, U>: CD, 
Op2<I, U>: CE, 
Op3<H, J, V>: CD, 
Op2<U, S>: CE, 
Op2<I, Q>: CE, 
Op2<W, I>: CE, 
Op3<D, J, M>: CC, 
K: CA, 
Op2<K, V>: CE, 
Op2<T, K>: CE, 
Op3<T, V, X>: CD, 
Op3<H, J, X>: CD, 
Op3<P, V, W>: CD, 
Op3<R, V, Z>: CD, 
Op3<R, T, X>: CD, 
S: CA, 
Op2<X, L>: CE, 
Z: CA, 
Op2<J, V>: CE, 
Op3<E, Q, V>: CC, 
Op3<C, G, V>: CD, 
Op3<M, Q, X>: CD, 
Op3<L, X, Z>: CC, 
Op2<L, Y>: CE, 
Op3<F, Q, Y>: CC, 
Op2<X, Y>: CB, 
Op3<C, I, U>: CD, 
Op2<X, G>: CE, 
Op2<M, V>: CE, 
Op3<B, E, J>: CD, 
Op2<Y, Z>: CB, 
Op3<C, K, M>: CD, 
Op3<C, D, L>: CD, 
Op3<B, L, Q>: CD, 
Op2<E, D>: CE, 
Op3<B, F, J>: CD, 
Op3<P, V, Z>: CD, 
Op2<Q, I>: CE, 
Op2<S, T>: CE, 
Op2<S, O>: CE, 
Op2<V, S>: CE, 
Op3<C, D, J>: CD, 
Op2<Q, R>: CB, 
Op3<C, H, U>: CD, 
Op3<A, O, Q>: CD, 
Op2<V, K>: CE, 
Op2<T, V>: CE, 
Op2<H, I>: CB, 
Op2<K, A>: CE, 
Op2<L, J>: CE, 
Op3<C, X, Z>: CD, 
Op3<D, Q, W>: CD, 
Op3<K, Q, V>: CD, 
Op2<Q, G>: CE, 
Op3<B, V, W>: CD, 
Op3<C, I, S>: CD, 
Op2<Z, Q>: CE, 
Op3<C, U, Z>: CD, 
Op3<R, V, X>: CD, 
Op3<B, F, Q>: CD, 
Op3<C, L, Y>: CD, 
Op3<A, H, Q>: CD, 
Op2<G, Q>: CE, 
Op2<S, D>: CE, 
Op3<C, H, L>: CD, 
Op3<B, K, L>: CD, 
Op2<L, F>: CE, 
W: CA, 
Op3<J, N, R>: CC, 
Op3<B, Q, S>: CD, 
Op2<A, L>: CE, 
Op2<W, X>: CE, 
Op3<C, E, Z>: CD, 
Op2<W, V>: CE, 
Op2<I, L>: CE, 
Op2<Y, J>: CE, 
Op3<C, K, S>: CD, 
Op3<P, Q, Z>: CD, 
Op3<P, U, V>: CD, 
Op3<C, L, Z>: CD, 
Op3<P, S, Z>: CD, 
Q: CA, 
Op2<K, I>: CE, 
Op2<K, Y>: CE, 
Op2<D, E>: CE, 
Op3<C, L, M>: CD, 
Op2<Q, O>: CE, 
Op3<B, S, U>: CD, 
Op2<H, L>: CE, 
Op3<B, W, X>: CD, 
Op3<G, O, R>: CC, 
Op2<O, X>: CE, 
Op3<A, Q, W>: CD, 
Op3<C, T, X>: CD, 
Op2<V, Q>: CE, 
Op2<S, M>: CE, 
Op3<P, S, X>: CD, 
Op2<F, X>: CE, 
Op2<Z, X>: CE, 
Op2<Q, D>: CE, 
Op3<P, Q, V>: CD, 
Op2<L, I>: CE, 
Op3<F, J, W>: CD, 
Op2<L, O>: CE, 
Op3<C, F, V>: CD, 
Op3<B, D, J>: CD, 
Op3<A, Q, Z>: CC, 
Op2<I, S>: CE, 
Op3<A, V, X>: CD, 
Op3<C, T, W>: CD, 
Op3<D, E, J>: CD, 
Op2<K, Z>: CE, 
Op3<K, L, T>: CC, 
Op3<C, Q, Y>: CD, 
Op2<Z, W>: CE, 
Op3<B, E, V>: CD, 
Op3<J, O, T>: CC, 
Op3<H, J, Q>: CD, 
Op3<K, S, Z>: CC, 
Op3<I, J, Q>: CD, 
Op2<E, K>: CE, 
Op3<C, K, Q>: CD, 
Op2<Q, U>: CE, 
Op3<C, Q, V>: CD, 
Op3<N, O, V>: CD, 
Op3<D, Q, Y>: CC, 
Op2<X, Z>: CE, 
Op3<O, Q, V>: CD, 
Op2<E, V>: CE, 
Op3<E, J, Q>: CD, 
Op3<G, J, V>: CD, 
Op3<R, T, U>: CD, 
Op2<W, S>: CE, 
Op2<V, F>: CE, 
Op3<C, S, Z>: CD, 
Op3<P, U, W>: CD, 
Op3<C, J, U>: CD, 
Op3<C, L, U>: CD, 
Op3<B, E, Q>: CD, 
Op2<V, G>: CE, 
Op3<C, S, U>: CD, 
Op3<A, E, W>: CD, 
Op3<M, Q, Y>: CD, 
Op2<B, C>: CB, 
Op3<F, J, L>: CD, 
Op2<I, E>: CE, 
Op3<I, Q, S>: CD, 
Op3<C, F, W>: CD, 
Op2<Z, J>: CE, 
Op3<A, J, U>: CD, 
Op3<R, U, W>: CD, 
Op3<I, L, Q>: CD, 
Op3<M, V, W>: CD, 
Op3<G, J, T>: CC, 
Op3<N, Q, W>: CD, 
Op2<J, F>: CE, 
Op3<F, Q, X>: CD, 
Op2<J, M>: CE, 
Op3<A, D, Q>: CD, 
Op3<F, J, S>: CD, 
Op2<O, W>: CE, 
Op2<V, M>: CE, 
Op3<C, I, K>: CD, 
Op2<J, K>: CB, 
Op2<M, K>: CE, 
Op2<V, U>: CE, 
Op3<R, S, Y>: CD, 
Op3<C, U, V>: CD, 
Op3<H, O, R>: CC, 
Op2<M, L>: CE, 
Op3<P, S, W>: CD, 
Op3<Q, S, W>: CC, 
Op2<E, G>: CE, 
Op3<T, V, W>: CD, 
Op3<P, V, Y>: CD, 
Op3<U, X, Z>: CC, 
Op3<C, W, X>: CD, 
Op3<K, L, Z>: CC, 
Op3<C, L, S>: CD, 
Op3<D, J, T>: CC, 
Op3<A, E, J>: CD, 
X: CA, 
Op3<C, H, W>: CD, 
Op3<L, W, Z>: CC, 
Op3<Q, S, U>: CC, 
Op2<L, D>: CE, 
A: CA, 
Op2<V, W>: CE, 
Op2<G, V>: CE, 
Op3<P, W, Z>: CD, 
Op3<C, T, U>: CD, 
Op3<F, O, R>: CC, 
Op3<C, O, W>: CD, 
Op2<D, W>: CE, 
Op2<I, W>: CE, 
Op2<L, V>: CE, 
Op2<O, L>: CE, 
Op3<J, Y, Z>: CC, 
Op3<C, E, L>: CD, 
Op3<R, S, V>: CD, 
Op3<I, J, S>: CD, 
Op2<J, X>: CE, 
Op3<D, Q, X>: CD, 
Op3<L, Q, U>: CC, 
Op3<F, Q, W>: CD, 
Op2<J, Q>: CE, 
Op3<A, K, V>: CD, 
Op2<Q, V>: CE, 
Op3<D, H, P>: CC, 
Op3<C, W, Z>: CD, 
Op2<X, V>: CE, 
Op2<W, M>: CE, 
Op2<J, B>: CE, 
Op3<C, H, X>: CD, 
Op2<M, W>: CE, 
Op3<I, J, K>: CD, 
Op2<Q, X>: CE, 
Op3<B, D, Q>: CD, 
Op3<C, V, Z>: CD, 
Op2<D, V>: CE, 
Op2<V, T>: CE, 
Op2<D, K>: CE, 
Op3<C, J, K>: CD, 
Op3<C, K, X>: CD, 
Op2<I, V>: CE, 
Op2<T, X>: CE, 
Op2<K, O>: CE, 
Op3<A, Q, V>: CD, 
Op3<D, E, Q>: CD, 
Op3<K, X, Z>: CC, 
T: CA, 
Op3<M, Q, W>: CD, 
Op3<H, O, P>: CC, 
Op3<C, D, S>: CD, 
Op3<B, Q, Y>: CD, 
Op3<H, J, M>: CC, 
Op3<C, I, J>: CD, 
Op2<K, Q>: CE, 
Op2<U, L>: CE, 
Op3<P, Q, R>: CC, 
Op3<K, Q, U>: CC, 
Op2<E, F>: CB, 
Op3<P, U, Z>: CD, 
Op3<G, Q, S>: CD, 
Op3<S, W, Z>: CC, 
Op2<A, J>: CE, 
Op3<C, J, X>: CD, 
Op2<W, Q>: CE, 
Op2<E, J>: CE, 
Op3<C, F, K>: CD, 
Op3<O, Q, U>: CD, 
Op2<S, A>: CE, 
Op2<E, O>: CE, 
Op3<B, J, O>: CD, 
Op2<S, X>: CE, 
Op3<D, J, Z>: CC, 
Op2<Q, K>: CE, 
Op2<K, J>: CE, 
Op3<G, Q, Y>: CC, 
Op2<V, J>: CE, 
Op3<I, L, V>: CD, 
Op3<A, E, Q>: CD, 
Op2<D, J>: CE, 
Op3<M, U, V>: CD, 
Op3<B, Q, W>: CD, 
Op3<N, V, X>: CD, 
Op3<C, G, W>: CD, 
Op3<K, M, N>: CC, 
Op3<G, Q, X>: CD, 
Op2<X, O>: CE, 
Op3<B, E, S>: CD, 
Op3<E, L, O>: CC, 
Op2<M, N>: CB, 
Op3<C, D, K>: CD, 
Op2<U, Z>: CE, 
Op3<G, Q, V>: CD, 
Op3<R, V, W>: CD, 
Op3<C, L, V>: CD, 
Op2<O, J>: CE, 
Op2<A, X>: CE, 
Op3<C, E, K>: CD, 
Op2<K, D>: CE, 
Op3<A, E, X>: CD, 
Op2<V, W>: CB, 
Op3<C, K, L>: CD, 
Op3<C, K, Z>: CD
{
    pub fn new() -> Self {Self(PhantomData)}
    pub fn succeed(self) {
        println!("You got the flag!")
    }
}

type Solution = Question<_, _, ...Fill this in...>;

fn main() {
    let solution = Solution::new();
    solution.succeed();
}
