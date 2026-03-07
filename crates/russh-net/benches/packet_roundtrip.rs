use criterion::{black_box, criterion_group, criterion_main, Criterion};
use russh_core::{PacketCodec, PacketFrame};

fn bench_packet_roundtrip(c: &mut Criterion) {
    let codec = PacketCodec::with_defaults();
    let frame = PacketFrame::new(vec![0x33; 32 * 1024]);
    c.bench_function("packet_encode_decode_32k", |b| {
        b.iter(|| {
            let encoded = codec
                .encode(black_box(&frame))
                .expect("packet encode should succeed");
            black_box(
                codec
                    .decode(&encoded)
                    .expect("packet decode should succeed"),
            )
        })
    });
}

criterion_group!(benches, bench_packet_roundtrip);
criterion_main!(benches);
