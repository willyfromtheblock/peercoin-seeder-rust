use peercoin_seeder_rust::db::storage::NodeDatabase;

#[tokio::test]
async fn test_real_testnet_data() {
    println!("\n=== Analyzing Real Testnet Data ===");

    // Connect to the actual testnet database
    let db = NodeDatabase::new("db/nodes_testnet.db").await.unwrap();
    let metrics = db.get_availability_metrics().await.unwrap();

    println!("Total nodes in database: {}", metrics.len());

    for (i, metric) in metrics.iter().enumerate() {
        println!("\n--- Node {}: {} ---", i + 1, metric.address);
        println!("Days seen: {}", metric.days_seen);
        println!("Total checks: {}", metric.total_checks);
        println!("Successful checks: {}", metric.successful_checks);
        println!("Availability: {:.1}%", metric.availability_score * 100.0);
        println!("Protocol version: {:?}", metric.last_protocol_version);
        println!("Last seen: {}", metric.last_seen);

        let hours_since_last_seen = (chrono::Utc::now() - metric.last_seen).num_hours();
        println!("Hours since last seen: {:.1}", hours_since_last_seen);

        // Check DNS criteria
        let min_protocol_version = 70018u32;
        let meets_criteria = metric.last_protocol_version.unwrap_or(0) >= min_protocol_version
            && metric.availability_score > 0.7
            && metric.days_seen >= 3
            && metric.total_checks >= 10
            && hours_since_last_seen < 24;

        println!("Meets DNS criteria: {}", meets_criteria);

        // Identify why nodes don't meet criteria
        if !meets_criteria {
            let mut reasons = Vec::new();

            if metric.last_protocol_version.unwrap_or(0) < 70018 {
                reasons.push(format!(
                    "Protocol version too old: {:?}",
                    metric.last_protocol_version
                ));
            }
            if metric.availability_score <= 0.7 {
                reasons.push(format!(
                    "Availability too low: {:.1}%",
                    metric.availability_score * 100.0
                ));
            }
            if metric.days_seen < 3 {
                reasons.push(format!("Not seen enough days: {}", metric.days_seen));
            }
            if metric.total_checks < 10 {
                reasons.push(format!("Not enough checks: {}", metric.total_checks));
            }
            if hours_since_last_seen >= 24 {
                reasons.push(format!(
                    "Last seen too long ago: {:.1}h",
                    hours_since_last_seen
                ));
            }

            println!("❌ Failing criteria: {}", reasons.join(", "));
        } else {
            println!("✅ Meets all DNS criteria!");
        }
    }

    let good_nodes = metrics
        .iter()
        .filter(|m| {
            let hours_since_last_seen = (chrono::Utc::now() - m.last_seen).num_hours();
            m.last_protocol_version.unwrap_or(0) >= 70018u32
                && m.availability_score > 0.7
                && m.days_seen >= 3
                && m.total_checks >= 10
                && hours_since_last_seen < 24
        })
        .count();

    println!(
        "\n🎯 Summary: {}/{} nodes meet DNS criteria",
        good_nodes,
        metrics.len()
    );

    // Additional analysis: why aren't more nodes becoming good?
    println!("\n=== Analysis of Non-Qualifying Nodes ===");

    let failing_by_reason = metrics
        .iter()
        .fold(std::collections::HashMap::new(), |mut acc, m| {
            let hours_since_last_seen = (chrono::Utc::now() - m.last_seen).num_hours();

            if m.last_protocol_version.unwrap_or(0) < 70018 {
                *acc.entry("old_protocol").or_insert(0) += 1;
            }
            if m.availability_score <= 0.7 {
                *acc.entry("low_availability").or_insert(0) += 1;
            }
            if m.days_seen < 3 {
                *acc.entry("not_enough_days").or_insert(0) += 1;
            }
            if m.total_checks < 10 {
                *acc.entry("not_enough_checks").or_insert(0) += 1;
            }
            if hours_since_last_seen >= 24 {
                *acc.entry("last_seen_too_old").or_insert(0) += 1;
            }

            acc
        });

    println!("Nodes failing by reason:");
    for (reason, count) in failing_by_reason {
        println!("  {}: {} nodes", reason, count);
    }
}
