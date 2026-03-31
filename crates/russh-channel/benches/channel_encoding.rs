use criterion::{Criterion, black_box, criterion_group, criterion_main};
use russh_channel::ChannelMessage;

fn bench_channel_data_to_frame(c: &mut Criterion) {
    let payload = vec![0x5a; 32 * 1024];
    c.bench_function("channel_data_to_frame_32k", |b| {
        b.iter(|| {
            let msg = ChannelMessage::Data {
                recipient_channel: 7,
                data: black_box(payload.clone()),
            };
            black_box(msg.to_frame().expect("channel frame encode should succeed"))
        })
    });
}

criterion_group!(benches, bench_channel_data_to_frame);
criterion_main!(benches);
