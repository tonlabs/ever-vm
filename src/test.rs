use ton_types::{SliceData, Cell};
use crate::executor::Engine;
use crate::stack::{savelist::SaveList, StackItem};

static DEFAULT_CAPABILITIES: u64 = 0x572e;

fn read_boc(filename: &str) -> Vec<u8> {
    let mut bytes = Vec::new();
    let mut file = std::fs::File::open(filename).unwrap();
    std::io::Read::read_to_end(&mut file, &mut bytes).unwrap();
    bytes
}

fn load_boc(filename: &str) -> Cell {
    let bytes = read_boc(filename);
    ton_types::read_single_root_boc(bytes).unwrap()
}

#[test]
fn test_simple() {
    let code = load_boc("asset/simple.boc");
    let mut ctrls = SaveList::default();
    let params = vec!(
        StackItem::int(0x76ef1ea), // magic - should be changed because of structure change
        StackItem::int(0), // actions
        StackItem::int(0), // msgs
        StackItem::int(0), // unix time
        StackItem::int(0), // logical time
        StackItem::int(0), // transaction time
        StackItem::int(0), // rand seed
        StackItem::tuple(vec!(
            StackItem::int(1000000000), // balance
            StackItem::None // balance other
        )),
        StackItem::default(), // myself
        StackItem::None,      // global config params
        StackItem::None,
        StackItem::int(0),
    );
    ctrls.put(7, &mut StackItem::tuple(vec!(StackItem::tuple(params)))).unwrap();

    let mut engine = Engine::with_capabilities(DEFAULT_CAPABILITIES).setup_with_libraries(
        SliceData::load_cell_ref(&code).unwrap(),
        Some(ctrls),
        None,
        None,
        vec!());
    engine.dump_ctrls(false);
    engine.execute().unwrap();
    let stack = engine.stack().get(0).as_integer().unwrap();
    println!("stack {:?}", stack);
    println!("C3 {:?}", engine.ctrl(3));
    let output = engine.ctrl(4).unwrap().as_cell().unwrap();
    println!("C4 {:?}", output);
    let actions = engine.ctrl(5).unwrap().as_cell().unwrap();
    println!("C5 {:?}", actions);
    println!("{:?}", engine.gas_used());
    assert_eq!(engine.gas_used(), 93);
}
