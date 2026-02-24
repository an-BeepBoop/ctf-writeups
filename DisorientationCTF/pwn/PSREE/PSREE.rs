use std::{
    cell::{Cell, UnsafeCell, RefCell},
    fmt::{Debug, Write},
    ops::Range,
    rc::Rc,
    sync::RwLock,
    sync::OnceLock,
};

trait Expression: Debug {
    fn name<'a>(&'a self) -> &'static str;
    fn compute_with_children<'a, 'b, 'c>(&'a self, v1: i64, v2: i64) -> i64 {
        unimplemented!()
    }
}
// todo cleanup
// pub fn sha_apply<'a, 'b>(hasher: &'a &'b RefCell<Sha512>, val_b: &'b ExprValue) -> &'a ExprValue {
//     match val_b {
//         ExprValue::Number(n) => hasher.borrow_mut().update(n.to_be_bytes()),
//         _ => {}
//     }
//     val_b
// }
// pub fn sha_apply<'a, 'b>(hasher: &'a &'b RefCell<Sha256>, val_b: &'b ExprValue) -> &'a ExprValue {
//     match val_b {
//         ExprValue::Number(n) => hasher.borrow_mut().update(n.to_be_bytes()),
//         _ => {}
//     }
//     val_b
// }
// le bytes seems a bit faster
pub fn sha_apply<'a, 'b>(hasher: &'a &'b RefCell<Sha256>, val_b: &'b ExprValue) -> &'a ExprValue {
    match val_b {
        ExprValue::Number(n) => hasher.borrow_mut().update(n.to_le_bytes()),
        _ => {}
    }
    val_b
}
pub fn attach_hash<'a, 'b, 'c, 'd>(x: &'a ExprValue, hasher: &'static &'static RefCell<Sha256>) -> &'b ExprValue {
    let f: for<'x> fn(_, &'x ExprValue) -> &'b ExprValue = sha_apply;
    f(hasher, x)
}
#[derive(Debug)]
struct Add;
#[derive(Debug)]
struct Minus;
#[derive(Debug)]
struct Mult;
#[derive(Debug)]
struct Div;
//dsstruc Quot

#[derive(Debug)]
struct PrintFlag;
impl Expression for Add {
    fn compute_with_children<'a, 'b, 'c>(&'a self, v1: i64, v2: i64) -> i64 {
        v1 + v2
    }
    fn name<'a>(&'a self) -> &'static str {
        "+"
    }
}
impl Expression for Minus {
    fn compute_with_children<'a, 'b, 'c>(&'a self, v1: i64, v2: i64) -> i64 {
        v1 - v2
    }
    fn name<'a>(&'a self) -> &'static str {
        "-"
    }
}
impl Expression for Mult {
    fn compute_with_children<'a, 'b, 'c>(&'a self, v1: i64, v2: i64) -> i64 {
        v1 * v2
    }
    fn name<'a>(&'a self) -> &'static str {
        "*"
    }
}
impl Expression for Div {
    fn compute_with_children<'a, 'b, 'c>(&'a self, v1: i64, v2: i64) -> i64 {
        v1 / v2
    }
    fn name<'a>(&'a self) -> &'static str {
        // "//"
        "/"
    }
}
impl Expression for PrintFlag {
    fn compute_with_children<'a, 'b, 'c>(&'a self, v1: i64, v2: i64) -> i64 {
        let flag_str = std::fs::read_to_string("flag.txt").unwrap();
        println!("{}", flag_str);
        0
    }
    fn name<'a>(&'a self) -> &'static str {
        "PRINT FLAG"
    }
}
#[derive(Debug)]
enum ExprValue {
    Expr(Box<dyn Expression>),
    Number(i64),
}
enum TreeRef<'a> {
    Expr(&'a Box<dyn Expression>),
    Number(&'a i64)
}
impl<'a> From<&'a ExprValue> for TreeRef<'a> {
    fn from(value: &'a ExprValue) -> Self {
        match value {
            ExprValue::Expr(e) => Self::Expr(&e),
            ExprValue::Number(i) => Self::Number(&i)
        }
    }
}

struct ExpressionTree<'a> {
    operation: TreeRef<'a>,
    left_child: Option<Box<ExpressionTree<'a>>>,
    right_child: Option<Box<ExpressionTree<'a>>>,
}
impl ExpressionTree<'_> {
    pub fn compute(&self, hasher: &'static &'static RefCell<Sha256>) -> i64 {
        match self.operation {
            TreeRef::Number(n) => {
                hasher.borrow_mut().update(n.to_le_bytes());
                *n
            },
            TreeRef::Expr(e) => e.compute_with_children(
                self.left_child.as_ref().map_or(0, |v| v.compute(hasher)),
                self.right_child.as_ref().map_or(0, |v| v.compute(hasher)),
            ),
        }
    }
}
impl<'a> Debug for ExpressionTree<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.operation {
            TreeRef::Number(n) => {
                f.write_str(n.to_string().as_str()).unwrap();
            }
            TreeRef::Expr(e) => {
                let name = e.name();
                if let Some(ref left_child) = self.left_child
                    && let Some(ref right_child) = self.right_child
                {
                    write!(f, "(({:?})) {} ({:?})", left_child, name, right_child).unwrap();
                }
            }
        }
        Ok(())
    }
}
fn get_slot_item() -> ExprValue {
    let mut input = String::new();
    loop {
        println!("Please enter a number or an arithmetic operator");
        std::io::stdin().read_line(&mut input).unwrap();
        let trimmed = input.trim();
        if let Ok(num) = trimmed.parse() {
            break ExprValue::Number(num);
        } else if trimmed == "+" {
            break ExprValue::Expr(Box::new(Add));
        } else if trimmed == "-" {
            break ExprValue::Expr(Box::new(Minus));
        } else if trimmed == "*" {
            break ExprValue::Expr(Box::new(Mult));
        } else if trimmed == "/" {
            break ExprValue::Expr(Box::new(Div));
        } else if trimmed == "pflag" {
            panic!("FLAG PRINTING NOT ALLOWED FOR NOW");
        } else {
            panic!("Unrecognised item");
        }
    }
}

fn recompute_tree<'a, 'b, 'c, 'd>(
    array: &'a [ExprValue],
    tree: &'b mut Option<ExpressionTree<'c>>,
    hasher: &'static &'static RefCell<Sha256>,
) -> &'a [ExprValue] {
    // just make a new one for now, bit too hard otherwise :(
    let mut leftover_array = array;
    let mut new_tree = None;
    while leftover_array.len() > 0 {
        match &leftover_array[0] {
            ExprValue::Number(n) => {
                // time to end it
                if new_tree.is_none() {
                    new_tree = Some(ExpressionTree {
                        operation: attach_hash(&leftover_array[0], hasher).into(),
                        left_child: None,
                        right_child: None,
                    });
                    leftover_array = &leftover_array[1..];
                }
                break;
            }
            ExprValue::Expr(e) => {
                if new_tree.is_none() {
                    let operation = attach_hash(&leftover_array[0], hasher).into();
                    leftover_array = &leftover_array[1..];
                    let mut left_child = None;
                    let mut right_child = None;
                    leftover_array = 
                        recompute_tree(leftover_array, &mut left_child, hasher);
                    leftover_array = 
                        recompute_tree(leftover_array, &mut right_child, hasher);
                    let left_child = left_child.map(Box::new);
                    let right_child = right_child.map(Box::new);
                    new_tree = Some(ExpressionTree {
                        operation,
                        left_child,
                        right_child,
                    })
                }
                break;
            }
        }
    }
    if let Some(new_tree) = new_tree {
        let _ = tree.insert(new_tree);
    }
    leftover_array
}
use sha2::{Sha256, Sha512, Digest};
use hex_literal::hex;
fn main() {
    let mut tracked: Vec<ExprValue> = Vec::new();
    let mut tree: Option<ExpressionTree> = None;
    let hasher: &'static &'static RefCell<Sha256> = (&*Box::leak(Box::new((&*Box::leak(Box::new(RefCell::new(Sha256::new())))))));
    println!(r#"
        _____   _____ _____  ______ ______ 
        |  __ \ / ____|  __ \|  ____|  ____|
        | |__) | (___ | |__) | |__  | |__   
        |  ___/ \___ \|  _  /|  __| |  __|  
        | |     ____) | | \ \| |____| |____ 
        |_|    |_____/|_|  \_\______|______|

        Welcome to the Perfectly Safe Rust Expression Evaluator!
        To use this program, first load operations and numbers into the queue using
        options (1) and (2). For example, (+) (1) (1) is a valid input.
        Then you can use (3) to prepare the expression tree, (4) to print it and
        (5) to compute the value. The computed value will be stored in the
        second slot.

        (6) can be used to see what you currently have in your queue.

        Valid operations are `+`, `-`, `*`, `/` and `pflag`.
    "#);
    loop {
        println!(r#"
        Would you like to:
        1. Edit slot
        2. Add item
        3. Prepare Tree
        4. Print tree
        5. Compute tree value and place in slot 2
        6. Print queued contents
        "#);
        let mut input_str = String::new();
        std::io::stdin().read_line(&mut input_str).unwrap();
        match input_str.trim_end_matches('\n') {
            "1" => {
                println!("Select which index to edit");
                let mut input_str = String::new();
                std::io::stdin().read_line(&mut input_str).unwrap();
                let index: usize = input_str.trim().parse().unwrap();
                if index >= tracked.len() {
                    continue;
                }
                tracked[index] = get_slot_item();
            }
            "2" => {
                tracked.push(get_slot_item());
            }
            "3" => {
                recompute_tree(&tracked, &mut tree, hasher);
            }
            "4" => {
                println!("{:?}", &tree);
            }
            "5" => {
                if let Some(ref tree) = tree {
                    let value = tree.compute(hasher);
                    if tracked.len() < 2 {
                        tracked.push(ExprValue::Number(value));
                    }
                    else {
                        tracked[1] = ExprValue::Number(value);
                    }
                
                    let hashing_output = hasher.borrow_mut().clone().finalize();
                    const CORRECT_HASH: [u8; 32] = hex!("d2698d824f52e8243d4c6a0c263758e7f6d7ac3fff48654dab8d044efb9fe7bc");
                    if hashing_output[..] == CORRECT_HASH {
                        // you did it! Here is the secret
                        tracked.push(ExprValue::Expr(Box::new(PrintFlag)));
                    }
                }
                else {
                    println!("No tree to compute value from");
                }
            },
            "6" => {
                println!("{:?}", tracked);
            },
            _ => continue,
        }
    }
}