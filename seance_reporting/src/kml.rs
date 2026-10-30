//! Geolocation exporters: KML (Google Earth) and GeoJSON.
//!
//! Autopsy ships a KML report module for mapping case GPS points; Séance
//! extracts GPS from EXIF metadata (`gps_lat`/`gps_lon`/`gps_altitude`). These
//! functions turn [`crate::report::GeoPoint`] values into mapping-tool formats.

use crate::report::GeoPoint;

/// Escape a string for inclusion in XML text content.
fn xml_esc(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

/// Render GPS points as a KML 2.2 document (Google Earth / GIS tooling).
///
/// Each point becomes a `<Placemark>` with the file label as its name and, when
/// present, path and timestamp in the description. Coordinates use KML order:
/// `longitude,latitude[,altitude]`.
///
/// `truncated` says the point list hit the query cap. It is written into the
/// document's own `<description>` because the export leaves the application:
/// opened in Google Earth by someone who never saw the report, a capped file is
/// otherwise indistinguishable from the complete set of places the evidence
/// puts the device.
pub fn render_kml(case_name: &str, points: &[GeoPoint], truncated: bool) -> String {
    let mut k = String::with_capacity(512 + points.len() * 256);
    k.push_str(r#"<?xml version="1.0" encoding="UTF-8"?>"#);
    k.push('\n');
    k.push_str(r#"<kml xmlns="http://www.opengis.net/kml/2.2">"#);
    k.push('\n');
    k.push_str(&format!(
        "<Document>\n<name>{} - Geolocation</name>\n",
        xml_esc(case_name)
    ));
    if truncated {
        k.push_str(&format!(
            "<description>{}</description>\n",
            xml_esc(&crate::report::geo_truncation_note(points.len()))
        ));
    }
    for p in points {
        let mut desc = String::new();
        if let Some(path) = &p.path {
            desc.push_str(&format!("Path: {}\n", path));
        }
        if let Some(ts) = &p.timestamp {
            desc.push_str(&format!("Timestamp: {}\n", ts));
        }
        let coord = match p.altitude {
            Some(alt) => format!("{:.7},{:.7},{:.1}", p.longitude, p.latitude, alt),
            None => format!("{:.7},{:.7}", p.longitude, p.latitude),
        };
        k.push_str("<Placemark>\n");
        k.push_str(&format!("<name>{}</name>\n", xml_esc(&p.label)));
        if !desc.is_empty() {
            k.push_str(&format!("<description>{}</description>\n", xml_esc(&desc)));
        }
        if let Some(ts) = &p.timestamp {
            k.push_str(&format!(
                "<TimeStamp><when>{}</when></TimeStamp>\n",
                xml_esc(ts)
            ));
        }
        k.push_str(&format!(
            "<Point><coordinates>{}</coordinates></Point>\n",
            coord
        ));
        k.push_str("</Placemark>\n");
    }
    k.push_str("</Document>\n</kml>\n");
    k
}

/// Render GPS points as a GeoJSON `FeatureCollection`.
///
/// `truncated` marks a capped point list. It becomes a top-level member of the
/// collection (GeoJSON permits foreign members) so the disclosure travels with
/// the file rather than being lost the moment it is opened outside Séance.
pub fn render_geojson(points: &[GeoPoint], truncated: bool) -> String {
    let features: Vec<serde_json::Value> = points
        .iter()
        .map(|p| {
            let mut coords = vec![
                serde_json::json!(p.longitude),
                serde_json::json!(p.latitude),
            ];
            if let Some(alt) = p.altitude {
                coords.push(serde_json::json!(alt));
            }
            serde_json::json!({
                "type": "Feature",
                "geometry": { "type": "Point", "coordinates": coords },
                "properties": {
                    "label": p.label,
                    "path": p.path,
                    "timestamp": p.timestamp,
                }
            })
        })
        .collect();
    let mut collection = serde_json::json!({
        "type": "FeatureCollection",
        "features": features,
    });
    if truncated {
        let obj = collection
            .as_object_mut()
            .expect("FeatureCollection is a JSON object");
        obj.insert("truncated".into(), serde_json::json!(true));
        obj.insert(
            "incomplete_reason".into(),
            serde_json::json!(crate::report::geo_truncation_note(points.len())),
        );
    }
    collection.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pt() -> GeoPoint {
        GeoPoint {
            label: "IMG_0001.jpg".into(),
            path: Some("/DCIM/IMG_0001.jpg".into()),
            latitude: 51.501364,
            longitude: -0.141890,
            altitude: Some(15.0),
            timestamp: Some("2023-06-01T12:00:00Z".into()),
        }
    }

    #[test]
    fn kml_has_placemark_and_kml_coord_order() {
        let k = render_kml("Case A", &[pt()], false);
        assert!(k.contains("<Placemark>"));
        assert!(k.contains("<name>IMG_0001.jpg</name>"));
        // KML order is lon,lat,alt
        assert!(k.contains("-0.1418900,51.5013640,15.0"));
        assert!(k.contains("<when>2023-06-01T12:00:00Z</when>"));
    }

    #[test]
    fn kml_escapes_xml_metacharacters() {
        let mut p = pt();
        p.label = "a & b <x>".into();
        let k = render_kml("C", &[p], false);
        assert!(k.contains("a &amp; b &lt;x&gt;"));
        assert!(!k.contains("<x>"));
    }

    #[test]
    fn geojson_is_valid_feature_collection() {
        let g = render_geojson(&[pt()], false);
        let v: serde_json::Value = serde_json::from_str(&g).unwrap();
        assert_eq!(v["type"], "FeatureCollection");
        assert_eq!(v["features"][0]["geometry"]["coordinates"][0], -0.141890);
        assert_eq!(v["features"][0]["geometry"]["coordinates"][1], 51.501364);
    }

    #[test]
    fn empty_points_still_valid() {
        let k = render_kml("Empty", &[], false);
        assert!(k.contains("</kml>"));
        let g = render_geojson(&[], false);
        let v: serde_json::Value = serde_json::from_str(&g).unwrap();
        assert_eq!(v["features"].as_array().unwrap().len(), 0);
    }

    /// B4-018: a capped export must say so inside the exported file. Before the
    /// fix both exporters emitted exactly the same bytes whether or not the
    /// query had hit its 100k ceiling.
    #[test]
    fn truncated_exports_carry_the_disclosure() {
        let k = render_kml("Case A", &[pt()], true);
        assert!(k.contains("<description>"));
        assert!(k.contains("AT LEAST"), "kml note missing: {k}");

        let g = render_geojson(&[pt()], true);
        let v: serde_json::Value = serde_json::from_str(&g).unwrap();
        assert_eq!(v["truncated"], serde_json::json!(true));
        assert!(v["incomplete_reason"]
            .as_str()
            .unwrap()
            .contains("AT LEAST"));
    }

    /// A complete export must NOT carry the disclosure: a warning that is always
    /// present is a warning nobody reads.
    #[test]
    fn complete_exports_carry_no_disclosure() {
        let k = render_kml("Case A", &[pt()], false);
        assert!(!k.contains("AT LEAST"));
        let g = render_geojson(&[pt()], false);
        let v: serde_json::Value = serde_json::from_str(&g).unwrap();
        assert!(v.get("truncated").is_none());
    }
}
