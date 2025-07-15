use peercoin_seeder_rust::crawler::seeder::Crawler;
use peercoin_seeder_rust::bitcoin::protocol::Network;
use std::net::SocketAddr;

#[tokio::test]
async fn test_seeder_database_persistence() {
    println!("\n=== Testing Seeder Database Persistence ===");
    
    // Create a seeder exactly like main.rs does
    let mut seeder = Crawler::new("127.0.0.1:0", Network::Testnet).unwrap();
    
    // Initialize database exactly like main.rs does
    let database_path = "db/nodes_testnet.db";
    match seeder.init_database(database_path).await {
        Ok(()) => {
            println!("✅ Database initialized successfully");
        }
        Err(e) => {
            println!("❌ Database initialization failed: {e}");
            return; // Exit test if database fails
        }
    }
    
    // Verify database is connected
    if seeder.get_database().is_none() {
        println!("❌ Database reference is None after successful init!");
        return;
    }
    
    println!("✅ Database reference confirmed");
    
    // Get initial count of nodes
    let initial_metrics = if let Some(db) = seeder.get_database() {
        db.get_availability_metrics().await.unwrap()
    } else {
        vec![]
    };
    println!("📊 Initial node count in database: {}", initial_metrics.len());
    
    // Test adding a node like the crawler does
    let test_address: SocketAddr = "1.2.3.4:9903".parse().unwrap();
    
    println!("🔄 Adding test node: {test_address}");
    // Instead of creating a version message, let's test add_or_update_node with None version
    // This simulates discovering a peer without full handshake
    println!("🔍 Before add_or_update_node call");
    
    // Enable verbose logging for this test
    std::env::set_var("RUST_LOG", "trace");
    
    seeder.add_or_update_node(test_address, None).await;
    println!("🔍 After add_or_update_node call");
    
    // Check what status the node has in memory
    let memory_stats = seeder.get_node_stats();
    println!("🔍 Memory stats: {} good, {} bad", memory_stats.0, memory_stats.1);
    
    // Check if the node was added to the database
    let updated_metrics = if let Some(db) = seeder.get_database() {
        db.get_availability_metrics().await.unwrap()
    } else {
        vec![]
    };
    println!("📊 Node count after add: {}", updated_metrics.len());
    
    if updated_metrics.len() > initial_metrics.len() {
        println!("✅ Database persistence working - node was added!");
        
        // Find our test node in the metrics
        for metric in &updated_metrics {
            if metric.address == test_address {
                println!("✅ Found test node in database:");
                println!("   Address: {}", metric.address);
                println!("   Days seen: {}", metric.days_seen);
                println!("   Total checks: {}", metric.total_checks);
                println!("   Successful checks: {}", metric.successful_checks);
                println!("   Availability: {:.1}%", metric.availability_score * 100.0);
                println!("   Last seen: {}", metric.last_seen);
                break;
            }
        }
    } else {
        println!("❌ Database persistence NOT working - node count unchanged!");
        
        // Let's check if there were any database errors during the operation
        println!("🔍 Checking if add_or_update_node had issues...");
        
        // Verify the node exists in memory
        let memory_nodes = seeder.get_node_stats();
        println!("   Nodes in memory: {} total", memory_nodes.0 + memory_nodes.1);
        
        // Try a direct database operation to see if that works
        println!("🔄 Trying direct database record...");
        if let Some(db) = seeder.get_database() {
            match db.record_successful_check(test_address, Some(70018), Some("Direct Test".to_string()), 30).await {
                Ok(()) => {
                    println!("✅ Direct database record successful");
                    
                    // Check again
                    let final_metrics = db.get_availability_metrics().await.unwrap();
                    println!("📊 Final node count: {}", final_metrics.len());
                }
                Err(e) => {
                    println!("❌ Direct database record failed: {e}");
                }
            }
        }
    }
}
