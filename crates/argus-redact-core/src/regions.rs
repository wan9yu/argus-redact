//! Chinese admin-region gazetteer + quasi-identifier coarsening (SSOT).
//!
//! Loads `data/regions/zh.ron` (GB/T 2260) once and exposes `coarsen()`, which
//! maps a span containing an admin region to its city/province ancestor —
//! the core of the lossy `generalize` strategy. Shared by PyO3 + wasm.
use std::collections::HashMap;
use std::sync::OnceLock;

use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct ZhRegionData {
    /// (name, level["province"|"city"|"district"], city_name, province_name)
    regions: Vec<(String, String, String, String)>,
}

fn zh_region_data() -> &'static ZhRegionData {
    static CELL: OnceLock<ZhRegionData> = OnceLock::new();
    CELL.get_or_init(|| {
        ron::from_str(include_str!("../data/regions/zh.ron"))
            .unwrap_or_else(|e| panic!("RON parse error in data/regions/zh.ron: {e}"))
    })
}

/// name → (city, province). Names are not globally unique across provinces (e.g.
/// 朝阳区 exists in 北京 and 辽宁朝阳市); first-by-load-order wins — acceptable for
/// a coarsening heuristic. Built once.
fn region_index() -> &'static HashMap<&'static str, (&'static str, &'static str)> {
    static CELL: OnceLock<HashMap<&'static str, (&'static str, &'static str)>> = OnceLock::new();
    CELL.get_or_init(|| {
        let mut m = HashMap::new();
        for (name, _level, city, province) in &zh_region_data().regions {
            m.entry(name.as_str())
                .or_insert((city.as_str(), province.as_str()));
        }
        m
    })
}

/// All region names sorted LONGEST-first (by char count), for greedy
/// longest-match scans.
fn region_names_longest_first() -> &'static [&'static str] {
    static CELL: OnceLock<Vec<&'static str>> = OnceLock::new();
    CELL.get_or_init(|| {
        let mut names: Vec<&'static str> =
            zh_region_data().regions.iter().map(|r| r.0.as_str()).collect();
        names.sort_by(|a, b| b.chars().count().cmp(&a.chars().count()).then(a.cmp(b)));
        names
    })
    .as_slice()
}

/// Coarsen `span` to the requested level. Finds the FINEST (longest) region name
/// contained in `span`, then returns its `city` (level="city", default) or
/// `province` (level="province") ancestor. Returns `None` if no region is found
/// (caller falls back to the type's default strategy).
pub fn coarsen(span: &str, level: &str) -> Option<String> {
    // Greedy longest-match: names are pre-sorted longest-first, so the first
    // name that appears in the span is the most specific (上海市浦东新区 >
    // 浦东新区 > 上海市) — break on first hit.
    let name = region_names_longest_first()
        .iter()
        .find(|&&n| span.contains(n))
        .copied()?;
    let (city, province) = region_index().get(name).copied()?;
    Some(match level {
        "province" => province.to_string(),
        _ => city.to_string(), // default "city"
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn coarsens_district_to_city_and_province() {
        assert_eq!(coarsen("杭州西湖区文一路100号", "city").as_deref(), Some("杭州市"));
        assert_eq!(coarsen("杭州西湖区文一路100号", "province").as_deref(), Some("浙江省"));
        assert_eq!(coarsen("上海浦东新区建国路100号", "city").as_deref(), Some("上海市"));
        assert_eq!(coarsen("广州天河区天河路", "province").as_deref(), Some("广东省"));
    }

    #[test]
    fn no_region_returns_none() {
        assert_eq!(coarsen("一段没有地名的文本", "city"), None);
    }

    #[test]
    fn gazetteer_loads_and_is_nonempty() {
        assert!(zh_region_data().regions.len() > 3000);
    }
}
