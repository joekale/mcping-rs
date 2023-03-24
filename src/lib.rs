use std::{
    sync::{mpsc, Arc, Mutex},
    thread, time::Duration,
};
pub struct ThreadPool {
    workers: Vec<Worker>,
    sender: mpsc::SyncSender<Job>,
}

type Job = Box<dyn FnOnce() + Send + 'static>;

impl ThreadPool {
    /// Create a new ThreadPool.
    ///
    /// The size is the number of threads in the pool.
    ///
    /// # Panics
    ///
    /// The `new` function will panic if the size is zero.
    pub fn new(size: usize) -> ThreadPool {
        assert!(size > 0);
        
        let (sender, receiver) = mpsc::sync_channel(0);

        let receiver = Arc::new(Mutex::new(receiver));

        let mut workers = Vec::with_capacity(size);

        for id in 0..size {
            workers.push(Worker::new(id, Arc::clone(&receiver)));
        }

        ThreadPool { workers, sender }
    }

    pub fn execute<F>(&self, f: F)
    where
        F: FnOnce() + Send + 'static,
    {
        let job = Box::new(f);

        self.sender.send(job).unwrap();
    }

    pub fn wait(&self) {
        let mut running: bool = true;
        while running {
            let mut threads_active = false;
            for worker in &self.workers {
                threads_active |= !worker.thread.is_finished();
            }
            running = threads_active
        }
    }
}

struct Worker {
    id: usize,
    thread: thread::JoinHandle<()>,
}

impl Worker {
    fn new(id: usize, receiver: Arc<Mutex<mpsc::Receiver<Job>>>) -> Worker {
        let thread = thread::spawn(move || loop {
            let job = match receiver.lock().unwrap().recv_timeout(Duration::new(1, 0)) {
                Ok(job) => job,
                Err(_) => break
            };
            job();
        });

        Worker { id, thread }
    }
}

