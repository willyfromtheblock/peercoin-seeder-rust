use peercoin_seeder_rust::crawler::seeder::Crawler;
use peercoin_seeder_rust::bitcoin::protocol::Network;

#[tokio::test]
async fn test_database_connection() {
    println!("\n=== Testing Database Connection ===");
    
    // Create a seeder
    let mut seeder = Crawler::new("127.0.0.1:0", Network::Testnet).unwrap();
    
    // Try to initialize the database
    let database_path = "db/nodes_testnet.db";
    println!("Attempting to initialize database at: {}", database_path);
    
    match seeder.init_database(database_path).await {
        Ok(()) => {
            println!("✅ Database initialization successful!");
            
            // Check if database reference is actually set
            if seeder.get_database().is_some() {
                println!("✅ Database reference is properly set in seeder");
                
                // Try to get some metrics to verify connection works
                if let Some(db) = seeder.get_database() {
                    match db.get_availability_metrics().await {
                        Ok(metrics) => {
                            println!("✅ Database connection verified - found {} nodes", metrics.len());
                        }
                        Err(e) => {
                            println!("❌ Database query failed: {}", e);
                        }
                    }
                }
            } else {
                println!("❌ Database reference is None despite successful init!");
            }
        }
        Err(e) => {
            println!("❌ Database initialization failed: {}", e);
            println!("   This explains why database persistence isn't working!");
        }
    }
}

#[tokio::test]
async fn test_database_file_permissions() {
    println!("\n=== Testing Database File Access ===");
    
    let database_path = "db/nodes_testnet.db";
    
    // Check if file exists
    if std::path::Path::new(database_path).exists() {
        println!("✅ Database file exists: {}", database_path);
        
        // Check file permissions
        match std::fs::metadata(database_path) {
            Ok(metadata) => {
                println!("✅ File is readable: {}", metadata.permissions().readonly() == false);
                println!("   File size: {} bytes", metadata.len());
                
                // Try to create a new database connection
                use peercoin_seeder_rust::db::storage::NodeDatabase;
                match NodeDatabase::new(database_path).await {
                    Ok(_) => println!("✅ Direct database connection successful"),
                    Err(e) => println!("❌ Direct database connection failed: {}", e),
                }
            }
            Err(e) => {
                println!("❌ Cannot read file metadata: {}", e);
            }
        }
    } else {
        println!("❌ Database file does not exist: {}", database_path);
        
        // Check if directory exists
        if let Some(parent) = std::path::Path::new(database_path).parent() {
            if parent.exists() {
                println!("✅ Database directory exists: {}", parent.display());
            } else {
                println!("❌ Database directory missing: {}", parent.display());
            }
        }
    }
}
