use peercoin_seeder_rust::bitcoin::protocol::Network;
use peercoin_seeder_rust::crawler::seeder::Crawler;

/// Regression: nodes loaded from the DB on startup must NOT be counted as good
/// until the crawler confirms them with a real handshake. The old code called
/// update_last_seen() during load, recomputing status to Good from the stored
/// protocol version without any contact -- so `good` spiked on every restart
/// with unverified (often dead) nodes.
#[tokio::test]
async fn loaded_db_nodes_are_not_good_until_verified() {
    let mut seeder = Crawler::new("127.0.0.1:0", Network::Testnet).unwrap();
    seeder.init_database(":memory:").await.unwrap();

    // A node with good history on the standard testnet port (9903).
    let addr = "1.2.3.4:9903".parse().unwrap();
    seeder
        .get_database()
        .as_ref()
        .unwrap()
        .record_successful_check(addr, Some(70018), Some("t".to_string()), 30)
        .await
        .unwrap();

    seeder.load_nodes_from_database().await.unwrap();

    let (good, bad) = seeder.get_node_stats();
    assert_eq!(good + bad, 1, "node should be loaded into memory");
    assert_eq!(
        good, 0,
        "loaded node must stay Unknown until a real handshake, not fake-good"
    );
}
