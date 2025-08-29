

use crate::traits;
use std::sync::{
    Arc,
    RwLock
};

struct MyType {
    counter: Arc<RwLock<usize>>,
}

impl Drop for MyType {
    fn drop(&mut self) {
        *self.counter.clone().write().unwrap()-= 1;
    }
}

impl traits::MyTrait for MyType {
    fn borrow(&self) {
        *self.counter.clone().write().unwrap() += 1;
    }
}

#[test]
fn static_string() {
    let my_string: String = String::from("string content");
    // let s: &str = my_string[3];
} 