/// Compute Shannon entropy for a byte slice (0.0 to 8.0).
///
/// For large data (>1MB), samples first 64KB + middle 64KB + last 64KB.
pub fn compute_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }

    let sample = if data.len() > 1_048_576 {
        // Sample: first 64KB + middle 64KB + last 64KB
        let chunk = 65_536;
        let mid = data.len() / 2;
        let mid_start = mid.saturating_sub(chunk / 2);
        let end_start = data.len().saturating_sub(chunk);

        let mut sampled = Vec::with_capacity(chunk * 3);
        sampled.extend_from_slice(&data[..chunk.min(data.len())]);
        sampled.extend_from_slice(&data[mid_start..mid_start + chunk.min(data.len() - mid_start)]);
        sampled.extend_from_slice(&data[end_start..]);
        sampled
    } else {
        data.to_vec()
    };

    compute_entropy_raw(&sample)
}

fn compute_entropy_raw(data: &[u8]) -> f64 {
    let mut histogram = [0u64; 256];
    for &byte in data {
        histogram[byte as usize] += 1;
    }

    let total = data.len() as f64;
    let mut entropy = 0.0;

    for &count in &histogram {
        if count > 0 {
            let p = count as f64 / total;
            entropy -= p * p.log2();
        }
    }

    entropy
}

/// Classify entropy value into human-readable categories.
pub fn classify_entropy(entropy: f64) -> &'static str {
    if entropy > 7.9 {
        "very_high"
    } else if entropy > 7.0 {
        "high"
    } else if entropy >= 4.0 {
        "medium"
    } else {
        "low"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_entropy_zeros() {
        let data = vec![0u8; 1024];
        assert_eq!(compute_entropy(&data), 0.0);
    }

    #[test]
    fn test_entropy_single_byte() {
        let data = vec![0x42u8; 1024];
        assert_eq!(compute_entropy(&data), 0.0);
    }

    #[test]
    fn test_entropy_uniform() {
        // All 256 byte values equally distributed -> entropy close to 8.0
        let mut data = Vec::with_capacity(256 * 100);
        for _ in 0..100 {
            for b in 0..=255u8 {
                data.push(b);
            }
        }
        let e = compute_entropy(&data);
        assert!((e - 8.0).abs() < 0.01, "Expected ~8.0, got {}", e);
    }

    #[test]
    fn test_entropy_two_values() {
        // Equal split of two values -> entropy = 1.0
        let mut data = Vec::with_capacity(1000);
        data.resize(500, 0u8);
        data.resize(1000, 1u8);
        let e = compute_entropy(&data);
        assert!((e - 1.0).abs() < 0.01, "Expected ~1.0, got {}", e);
    }

    #[test]
    fn test_classify_entropy() {
        assert_eq!(classify_entropy(2.0), "low");
        assert_eq!(classify_entropy(5.5), "medium");
        assert_eq!(classify_entropy(7.5), "high");
        assert_eq!(classify_entropy(7.95), "very_high");
    }

    #[test]
    fn test_entropy_empty() {
        assert_eq!(compute_entropy(&[]), 0.0);
    }
}
