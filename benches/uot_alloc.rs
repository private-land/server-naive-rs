//! Benchmark: UoT input loop allocation strategy.
//!
//! Measures the overhead of per-packet `vec![0u8; len]` (old code) vs.
//! a single pre-allocated `vec![0u8; 65535]` reused each iteration (new code).

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};

/// Simulate N packets with per-packet heap allocation (old behaviour).
fn per_packet_alloc(n: usize, packet_size: usize) -> usize {
    let mut total = 0usize;
    for _ in 0..n {
        let buf = vec![0u8; packet_size];
        total += buf.len();
    }
    total
}

/// Simulate N packets with a single pre-allocated buffer (new behaviour).
fn preallocated(n: usize, packet_size: usize) -> usize {
    let buf = vec![0u8; 65535];
    let mut total = 0usize;
    for _ in 0..n {
        let slice = &buf[..packet_size];
        total += slice.len();
    }
    total
}

fn bench_uot_alloc(c: &mut Criterion) {
    // Typical UDP MTU 1400 bytes and a larger 8 KB packet
    for &pkt_size in &[1400usize, 8192] {
        let n = 10_000usize;
        let total_bytes = (n * pkt_size) as u64;

        let mut group = c.benchmark_group("uot_alloc");
        group.throughput(Throughput::Bytes(total_bytes));

        group.bench_with_input(
            BenchmarkId::new("per_packet_vec", format!("{pkt_size}B")),
            &(n, pkt_size),
            |b, &(n, sz)| b.iter(|| per_packet_alloc(n, sz)),
        );

        group.bench_with_input(
            BenchmarkId::new("preallocated", format!("{pkt_size}B")),
            &(n, pkt_size),
            |b, &(n, sz)| b.iter(|| preallocated(n, sz)),
        );

        group.finish();
    }
}

criterion_group!(benches, bench_uot_alloc);
criterion_main!(benches);
