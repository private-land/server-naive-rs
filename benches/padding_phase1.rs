//! Benchmark: NaivePaddedTransport Phase 1 read throughput.
//!
//! Measures how fast `NaivePaddedTransport` can decode the 8 padding frames
//! when the caller reads with a large buffer (32 KB — typical relay buffer size).
//!
//! BUG baseline:   scratch buffer caps each poll_read at 4 096 bytes →
//!                 ⌈32 768 / 4 096⌉ = 8 inner reads per frame × 8 frames = 64 reads.
//! FIX throughput: buf.take(read_data_rem) reads the full frame in 1 call →
//!                 8 frames = 8 reads total.

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use server_naive_rs::transport::NaivePaddedTransport;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Build 8 padded frames each containing `frame_data_size` bytes of payload.
/// Returns the raw on-wire bytes (header + data + zero padding).
fn build_8_frames(frame_data_size: u16) -> Vec<u8> {
    let mut wire = Vec::new();
    for _ in 0..8 {
        wire.extend_from_slice(&frame_data_size.to_be_bytes());
        wire.push(0u8); // padding size = 0
        wire.extend(std::iter::repeat_n(0x42u8, frame_data_size as usize));
    }
    wire
}

/// Decode `wire` through a `NaivePaddedTransport`, reading with `read_buf_size`.
/// Returns total bytes decoded (= 8 × frame_data_size).
async fn decode_frames(wire: &[u8], read_buf_size: usize) -> usize {
    let (tx, rx) = tokio::io::duplex(wire.len() + 64);
    let wire = wire.to_vec();
    tokio::spawn(async move {
        let mut w = tx;
        w.write_all(&wire).await.unwrap();
        w.shutdown().await.unwrap();
    });

    let mut dec = NaivePaddedTransport::new(rx);
    let mut buf = vec![0u8; read_buf_size];
    let mut total = 0usize;
    loop {
        let n = dec.read(&mut buf).await.unwrap();
        if n == 0 {
            break;
        }
        total += n;
    }
    total
}

fn bench_phase1_throughput(c: &mut Criterion) {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();

    // Benchmark with three frame sizes to show the impact of the scratch cap.
    // The 4 096-byte case is unaffected (frame ≤ scratch cap).
    // The 32 768-byte case shows the worst-case degradation (8× more reads).
    for &frame_kb in &[4u16, 8, 16, 32] {
        let frame_data_size = frame_kb * 1024;
        let wire = build_8_frames(frame_data_size);
        let total_data = 8 * frame_data_size as u64;

        let mut group = c.benchmark_group("padding_phase1");
        group.throughput(Throughput::Bytes(total_data));

        group.bench_with_input(
            BenchmarkId::new("decode_8_frames", format!("{frame_kb}KB_frames")),
            &(wire, frame_data_size as usize),
            |b, (wire, read_buf)| {
                b.iter(|| rt.block_on(decode_frames(wire, *read_buf * 2)));
            },
        );

        group.finish();
    }
}

criterion_group!(benches, bench_phase1_throughput);
criterion_main!(benches);
