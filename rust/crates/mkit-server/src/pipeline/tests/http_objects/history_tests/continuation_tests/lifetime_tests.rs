//! Token lifetime is independent of each page's structural proof window.
use super::*;

async fn advancing_clock<T>(
    clock: &ManualClock,
    future: impl std::future::Future<Output = T>,
) -> T {
    let started = tokio::time::Instant::now();
    let business_started = clock.now_ms();
    let mut future = std::pin::pin!(future);
    std::future::poll_fn(|cx| {
        clock.set(business_started + i64::try_from(started.elapsed().as_millis()).unwrap());
        future.as_mut().poll(cx)
    })
    .await
}

#[test]
fn continuation_walk_outlives_proof_window_with_advancing_business_clock() {
    let (mut fx, commits, _, _) = history(52, 0, 1, false);
    enable(&mut fx);
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .start_paused(true)
        .build()
        .unwrap();
    for writer in [false, true] {
        fx.clock.set(T0);
        let started = fx.clock.now_ms();
        let mut token: Option<HistoryContinuation> = None;
        let mut expiry = None;
        let mut output = Vec::new();
        let mut pages = 0;
        loop {
            let page_started = fx.clock.now_ms();
            in_view(&fx, writer, |reader| {
                fx.pipe.meta.latency_ms.store(155, Ordering::SeqCst);
                fx.pipe.blobs.latency_ms.store(155, Ordering::SeqCst);
                let mut session = ReaderSession::default();
                let page = runtime
                    .block_on(advancing_clock(
                        fx.clock.as_ref(),
                        reader.walk_history_page_in(
                            &mut session,
                            HEAD,
                            token.as_ref().map(|token| token.token.expose()),
                            10,
                        ),
                    ))
                    .unwrap()
                    .expect("all pages remain accessible within the token lifetime");
                fx.pipe.meta.latency_ms.store(0, Ordering::SeqCst);
                fx.pipe.blobs.latency_ms.store(0, Ordering::SeqCst);
                assert!(
                    fx.clock.now_ms() > page_started,
                    "waits advance business time"
                );
                assert!(fx.clock.now_ms() - page_started < 60_000);
                assert!(!session.proofs.contains(&id(commits.last().unwrap())));
                for returned in page.commits {
                    let expected = &commits[commits.len() - 1 - output.len()];
                    assert_eq!(returned.id, id(expected));
                    assert_eq!(returned.canonical, serialize(expected).unwrap());
                    output.push(returned.id);
                }
                if let Some(next) = &page.next {
                    assert_eq!(
                        *expiry.get_or_insert(next.expires_at_ms),
                        next.expires_at_ms
                    );
                }
                token = page.next;
            });
            pages += 1;
            if token.is_none() {
                break;
            }
            fx.clock.advance(5_000);
        }
        assert_eq!(pages, 6);
        assert_eq!(output, commits.iter().rev().map(id).collect::<Vec<_>>());
        assert!(fx.clock.now_ms() - started > 60_000);
        assert!(u64::try_from(fx.clock.now_ms()).unwrap() < expiry.unwrap());
        println!(
            "continued walk owner={writer}: pages={pages}, elapsed_ms={}",
            fx.clock.now_ms() - started
        );
    }
}

#[test]
fn continuation_fixed_ttl_survives_proof_expiry_and_refuses_at_expiry() {
    let (mut fx, _, _, _) = history(4, 0, 1, false);
    fx.pipe.cfg.history_tokens = Some(
        HistoryTokenConfig::new(
            zeroize::Zeroizing::new([101; 32]),
            "test-backend".into(),
            120_000,
        )
        .unwrap(),
    );
    let token = first(&fx, false, 1);
    assert_eq!(token.expires_at_ms, u64::try_from(T0 + 120_000).unwrap());
    fx.clock.set(T0 + 119_999);
    in_view(&fx, false, |reader| {
        let page = block_on(reader.walk_history_page_in(
            &mut ReaderSession::default(),
            HEAD,
            Some(token.token.expose()),
            1,
        ))
        .unwrap()
        .unwrap();
        assert_eq!(page.next.unwrap().expires_at_ms, token.expires_at_ms);
    });
    fx.clock.set(T0 + 120_000);
    reject(&fx, false, token.token.expose());
    reject(&fx, false, token.token.expose());
}
