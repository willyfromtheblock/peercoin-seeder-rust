use peercoin_seeder_rust::db::storage::NodeDatabase;

#[tokio::test]
async fn test_database_direct_operations() {
    println!("\n=== Testing Direct Database Operations ===");

    // Use in-memory database for CI compatibility
    let database_path = ":memory:";
    let db = NodeDatabase::new(database_path).await.unwrap();

    // First, check what's currently in the database
    println!("📊 Checking current database state...");
    let initial_metrics = db.get_availability_metrics().await.unwrap();
    println!("   Initial metrics count: {}", initial_metrics.len());

    for (i, metric) in initial_metrics.iter().enumerate() {
        println!(
            "   Node {}: {} (last seen: {})",
            i + 1,
            metric.address,
            metric.last_seen
        );
    }

    // Add a test node directly to database
    let test_address = "9.8.7.6:9903".parse().unwrap();
    println!("\n🔄 Recording successful check for: {}", test_address);

    match db
        .record_successful_check(test_address, Some(70018), Some("Test".to_string()), 30)
        .await
    {
        Ok(()) => println!("✅ Direct record successful"),
        Err(e) => println!("❌ Direct record failed: {}", e),
    }

    // Check database again
    println!("\n📊 Checking database after direct record...");
    let updated_metrics = db.get_availability_metrics().await.unwrap();
    println!("   Updated metrics count: {}", updated_metrics.len());

    for (i, metric) in updated_metrics.iter().enumerate() {
        println!(
            "   Node {}: {} (last seen: {})",
            i + 1,
            metric.address,
            metric.last_seen
        );
    }

    // Check if our test node is there
    if updated_metrics.iter().any(|m| m.address == test_address) {
        println!("✅ Test node found in metrics!");
    } else {
        println!("❌ Test node NOT found in metrics");

        // Let's check the raw database to see what's actually stored
        println!("\n🔍 Checking raw database entries...");
        // This would require direct SQL access, but let's see if there's an issue with the time window
        println!("   Current time: {}", chrono::Utc::now());
        println!(
            "   30 days ago: {}",
            chrono::Utc::now() - chrono::Duration::days(30)
        );
    }
}

#[tokio::test]
async fn test_database_time_window() {
    println!("\n=== Testing Database Time Window Logic ===");

    // Use in-memory database for CI compatibility
    let database_path = ":memory:";
    let db = NodeDatabase::new(database_path).await.unwrap();

    // Record a test entry and immediately check if it appears
    let test_address = "5.4.3.2:9903".parse().unwrap();

    println!("🔄 Recording test entry for: {}", test_address);
    db.record_successful_check(test_address, Some(70018), Some("TimeTest".to_string()), 30)
        .await
        .unwrap();

    // Sleep briefly to ensure the record is committed
    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

    // Check if it appears in metrics immediately
    let metrics = db.get_availability_metrics().await.unwrap();

    if let Some(metric) = metrics.iter().find(|m| m.address == test_address) {
        println!("✅ New entry found in metrics immediately");
        println!("   Address: {}", metric.address);
        println!("   Last seen: {}", metric.last_seen);
        println!("   Days seen: {}", metric.days_seen);
        println!("   Total checks: {}", metric.total_checks);
    } else {
        println!("❌ New entry NOT found in metrics");
        println!("   This suggests a time window or aggregation issue");
    }
}
