use clap::*;
use crossbeam::channel::{unbounded, Receiver, Sender};
use lazy_static::*;
use rand::prelude::*;
use rocksdb::{DBWithThreadMode, MultiThreaded, WriteOptions};
use std::{
	path::PathBuf,
	sync::{
		atomic::{compiler_fence, AtomicBool, AtomicU64, Ordering::SeqCst},
		Arc,
	},
	thread,
	time::{Duration, Instant},
};

lazy_static! {
	static ref DATA: Vec<u8> = random_data(1024);
	static ref ARGS: Args = Args::parse();
}

#[derive(Parser, Debug, Clone)]
#[command(version, about, long_about = None)]
struct Args {

	#[arg(short, long)]
	threads: u64,

	/// Read ratio
	#[arg(short, long)]
	read_ratio: f64,

	/// Database path
	#[arg(short, long)]
	db_path: String,
}

pub fn main() {
	let _args = ARGS.clone();
	thread::spawn(run);
	thread::spawn(counter);
	loop {
		thread::sleep(Duration::from_secs(10));
	}
}

type DB = Arc<DBWithThreadMode<MultiThreaded>>;
static COUNT: AtomicU64 = AtomicU64::new(0);
static DROPPED: AtomicU64 = AtomicU64::new(0);
static DONE: AtomicBool = AtomicBool::new(false);

fn counter() {
	while !DONE.load(SeqCst) {
		let count = COUNT.swap(0, SeqCst);
		let dropped = DROPPED.swap(0, SeqCst);
		println!("Count: {}, Dropped: {}", count, dropped);
		thread::sleep(Duration::from_secs(1));
	}
	thread::sleep(Duration::from_secs(2));
}

fn random_data(sz: usize) -> Vec<u8> {
	let mut data: Vec<u8> = vec![0u8; sz];
	let mut rng = thread_rng();
	for d in &mut data {
		*d = rng.gen();
	}
	data
}

fn random_idx_bounds(l: usize, rng: &mut ThreadRng) -> (usize, usize) {
	let a: usize = rng.gen_range(0..l);
	let b: usize = rng.gen_range(0..l);
	let mut bounds = (a, b);
	if bounds.0 > bounds.1 {
		bounds = (bounds.1, bounds.0);
	}
	bounds
}

fn do_read(db: &DB, key: u64) -> Option<Vec<u8>> {
	compiler_fence(SeqCst);
	let res = db.get(key.to_be_bytes()).unwrap()?;
	compiler_fence(SeqCst);
	COUNT.fetch_add(1, SeqCst);
	Some(res.clone())
}

fn do_write(db: &DB, key: u64, slice: &[u8]) {
	let mut opt = WriteOptions::default();
	opt.set_sync(false);
	compiler_fence(SeqCst);
	db.put_opt(key.to_be_bytes(), slice, &opt).unwrap();
	compiler_fence(SeqCst);
	COUNT.fetch_add(1, SeqCst);
}

fn do_work(
	db: DB,
	read_ratio: f64,
	out: Sender<Vec<u8>>,
) {
	let data: &'static [u8] = DATA.as_slice();

	let mut rng = thread_rng();

	let bounds = random_idx_bounds(data.len(), &mut rng);
	let mut key = 0;
	loop {

		key += 1;
		let read: bool = if key <= 1000 {
			false
		} else {
			if key == 1001 {
				println!("Got to 1000");
			}
			rng.gen::<f64>() < read_ratio
		};
		let read_key = if read {
			rng.gen_range(0..key - 1000)
		} else {
			0
		};

		if read {
			if let Some(vec) = do_read(&db, read_key) {
				out.send(vec).unwrap();
				continue;
			}
		}

		let slice = &data[bounds.0..bounds.1];
		do_write(&db, key, slice);
	}
}

fn some_sink(rx: Receiver<Vec<u8>>) {
	let mut now = Instant::now();
	loop {
		if let Ok(v) = rx.try_recv() {
			if now.elapsed().as_secs_f64() > 1. {
				now = Instant::now();
			}
			drop(v);
		}
	}
}

fn setup_db(path: PathBuf) -> DB {
	let _ = std::fs::remove_dir_all(&path);
	let db = DBWithThreadMode::<MultiThreaded>::open_default(path).unwrap();
	let mut opt = WriteOptions::default();
	opt.set_sync(true);
	opt.disable_wal(false);
	Arc::new(db)
}

fn run() {
	let threads = ARGS.threads;
	let read_ratio = ARGS.read_ratio;
	let db_path = &ARGS.db_path;

	let (tx, rx) = unbounded();
	thread::spawn(move || some_sink(rx));
	let mut handles = Vec::new();
	let _ = std::fs::remove_dir_all(db_path);
	let db = setup_db(PathBuf::from(db_path));
	for _tid in 0..threads {
		let this_db = db.clone();
		let tx = tx.clone();
		handles.push(thread::spawn(move || {
			do_work(this_db, read_ratio, tx);
		}));
	}

	for h in handles {
		let _ = h.join();
	}
}

//fn driver_handle(msg: Message) -> Message {
//	match msg {
//		Message::Run => {
//			thread::spawn(run);
//			Message::Ok
//		}
//		Message::Done => {
//			println!("Exiting");
//			DONE.store(true, SeqCst);
//			Message::Ok
//		}
//		_ => panic!("unhandled message"),
//	}
//}
