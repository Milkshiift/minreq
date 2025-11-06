use std::thread;
use std::time::{Duration, Instant};
use tiny_http::{Server, Response};

const SAMPLES: u32 = 200;
const SERVER_ADDR: &str = "127.0.0.1:9876";

fn start_server() {
    let server = Server::http(SERVER_ADDR).expect("Failed to start server");
    println!("tiny_http server listening on http://{}", SERVER_ADDR);

    thread::spawn(move || {
        for request in server.incoming_requests() {
            let path = request.url();
            let size: usize = path
                .trim_start_matches("/bytes/")
                .parse()
                .unwrap_or(0);

            let payload = vec![0u8; size];
            let response = Response::from_data(payload);

            let _ = request.respond(response);
        }
    });

    thread::sleep(Duration::from_millis(100));
}

fn main() {
    println!("--- minreq performance benchmark ---");
    println!("Running {} samples for each payload size...\n", SAMPLES);

    start_server();

    let scenarios = vec![
        ("small", 1_000),       // 1 KB
        ("medium", 10_000),    // 10 KB
        ("large", 100_000),   // 100 MB
    ];

    println!("{:<10} | {:>10} | {:>10} | {:>10} | {:>10} | {:>12}",
             "Scenario", "Size (B)", "Min", "Max", "Average", "Throughput");
    println!("{}", "-".repeat(78));

    for (name, size) in scenarios {
        let url = format!("http://{}/bytes/{}", SERVER_ADDR, size);
        let mut durations: Vec<Duration> = Vec::with_capacity(SAMPLES as usize);

        minreq::get(&url).send().unwrap();

        for _ in 0..SAMPLES {
            let start = Instant::now();
            let response = minreq::get(&url).send().unwrap();
            let duration = start.elapsed();

            let _ = response.as_bytes();

            durations.push(duration);
        }

        let total_duration: Duration = durations.iter().sum();
        let avg_duration = total_duration / SAMPLES;
        let min_duration = *durations.iter().min().unwrap();
        let max_duration = *durations.iter().max().unwrap();

        let total_bytes_transferred = size as f64 * SAMPLES as f64;
        let total_secs = total_duration.as_secs_f64();
        let throughput_mb_s = (total_bytes_transferred / 1_000_000.0) / total_secs;

        println!("{:<10} | {:>10} | {:>10.2?} | {:>10.2?} | {:>10.2?} | {:>11.2} MB/s",
                 name,
                 size,
                 min_duration,
                 max_duration,
                 avg_duration,
                 throughput_mb_s);
    }
}