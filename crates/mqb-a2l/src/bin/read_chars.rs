//! Test reading CHARACTERISTIC values from real firmware + A2L data.
use std::time::Instant;
use mqb_a2l::reader::{AddressMap, CharacteristicValues, make_resolver, read_characteristic};
use mqb_a2l::CharacteristicType;

fn main() {
    let a2l_path = std::env::args().nth(1).unwrap_or_else(|| {
        "example.a2l".to_string()
    });
    let bin_path = std::env::args().nth(2).unwrap_or_else(|| {
        "example.bin".to_string()
    });

    eprintln!("Loading A2L...");
    let t0 = Instant::now();
    let a2l_bytes = std::fs::read(&a2l_path).expect("read A2L");
    let a2l = mqb_a2l::parse(&a2l_bytes).expect("parse A2L");
    eprintln!("  {} characteristics in {:.2?}", a2l.characteristics.len(), t0.elapsed());

    eprintln!("Loading binary...");
    let binary = std::fs::read(&bin_path).expect("read binary");
    eprintln!("  {} bytes", binary.len());

    // Simos18 address map: (base_addr, file_offset, length)
    let address_map: AddressMap = vec![
        (0x80000000, 0x000000, 0x01C000), // block 0 (SBOOT)
        (0x8001C000, 0x01C000, 0x023E00), // block 1 (CBOOT)
        (0x80040000, 0x040000, 0x0FFC00), // block 2 (ASW1)
        (0x80140000, 0x140000, 0x0BFC00), // block 3 (ASW2)
        (0x80880000, 0x280000, 0x07FC00), // block 4 (ASW3)
        (0xA0800000, 0x200000, 0x07FC00), // block 5 (CAL)
    ];
    let resolve = make_resolver(&address_map);

    // Read some VALUE characteristics
    eprintln!("\n=== Sample VALUE characteristics ===");
    let mut value_count = 0;
    for ch in a2l.characteristics.iter().filter(|c| c.char_type == CharacteristicType::Value) {
        if value_count >= 10 { break; }
        if let Some(CharacteristicValues::Scalar(v)) = read_characteristic(ch, &a2l, &binary, &resolve) {
            let cm = a2l.compu_methods.get(&ch.compu_method_ref);
            let unit = cm.map(|c| c.unit.as_str()).unwrap_or("");
            eprintln!("  {:40} = {:.6} {}", ch.name, v, unit);
            value_count += 1;
        }
    }

    // Read some CURVE characteristics
    eprintln!("\n=== Sample CURVE characteristics ===");
    let mut curve_count = 0;
    for ch in a2l.characteristics.iter().filter(|c| c.char_type == CharacteristicType::Curve) {
        if curve_count >= 3 { break; }
        if let Some(CharacteristicValues::Curve { x, y }) = read_characteristic(ch, &a2l, &binary, &resolve) {
            let cm = a2l.compu_methods.get(&ch.compu_method_ref);
            let unit = cm.map(|c| c.unit.as_str()).unwrap_or("");
            eprintln!("  {} ({} points, unit={}):", ch.name, x.len(), unit);
            for (xi, yi) in x.iter().zip(y.iter()).take(6) {
                eprintln!("    x={:.2}  y={:.6}", xi, yi);
            }
            if x.len() > 6 { eprintln!("    ..."); }
            curve_count += 1;
        }
    }

    // Read some MAP characteristics
    eprintln!("\n=== Sample MAP characteristics ===");
    let mut map_count = 0;
    for ch in a2l.characteristics.iter().filter(|c| c.char_type == CharacteristicType::Map) {
        if map_count >= 2 { break; }
        if let Some(CharacteristicValues::Map { x, y, z }) = read_characteristic(ch, &a2l, &binary, &resolve) {
            let cm = a2l.compu_methods.get(&ch.compu_method_ref);
            let unit = cm.map(|c| c.unit.as_str()).unwrap_or("");
            eprintln!("  {} ({}x{}, unit={}):", ch.name, x.len(), y.len(), unit);
            // Print header
            eprint!("    {:>8}", "");
            for xi in x.iter().take(6) { eprint!(" {:>8.2}", xi); }
            if x.len() > 6 { eprint!("  ..."); }
            eprintln!();
            // Print rows
            for (yi_idx, yi) in y.iter().enumerate().take(6) {
                eprint!("    {:>8.2}", yi);
                for zv in z[yi_idx].iter().take(6) {
                    eprint!(" {:>8.4}", zv);
                }
                if x.len() > 6 { eprint!("  ..."); }
                eprintln!();
            }
            if y.len() > 6 { eprintln!("    ..."); }
            map_count += 1;
        }
    }

    // Count successful reads by type, with failure breakdown
    eprintln!("\n=== Read success rates by type ===");
    let mut by_type: std::collections::HashMap<&str, (u32, u32)> = std::collections::HashMap::new();
    let mut failed_examples: Vec<String> = Vec::new();
    for ch in &a2l.characteristics {
        let label = match ch.char_type {
            CharacteristicType::Value => "VALUE",
            CharacteristicType::Curve => "CURVE",
            CharacteristicType::Map => "MAP",
            CharacteristicType::ValBlk => "VAL_BLK",
            CharacteristicType::Ascii => "ASCII",
            CharacteristicType::Cuboid => "CUBOID",
            CharacteristicType::Cube4 => "CUBE_4",
            CharacteristicType::Cube5 => "CUBE_5",
        };
        let entry = by_type.entry(label).or_insert((0, 0));
        entry.0 += 1;
        if read_characteristic(ch, &a2l, &binary, &resolve).is_some() {
            entry.1 += 1;
        } else if failed_examples.len() < 30 {
            let addr_ok = resolve(ch.address).is_some();
            let layout_ok = a2l.record_layouts.contains_key(&ch.deposit);
            failed_examples.push(format!(
                "  FAIL {:40} type={:8} addr={:#010X} addr_ok={} layout_ok={} deposit={}",
                ch.name, label, ch.address, addr_ok, layout_ok, ch.deposit
            ));
        }
    }
    let mut total = 0u32;
    let mut ok = 0u32;
    let mut types: Vec<_> = by_type.iter().collect();
    types.sort_by_key(|(name, _)| *name);
    for (name, (t, s)) in &types {
        let pct = 100.0 * *s as f64 / *t as f64;
        eprintln!("  {name:8}  {s:>6} / {t:<6}  ({pct:.1}%)");
        total += t;
        ok += s;
    }
    eprintln!("  --------");
    eprintln!("  TOTAL    {:>6} / {:<6}  ({:.1}%)", ok, total, 100.0 * ok as f64 / total as f64);

    if !failed_examples.is_empty() {
        eprintln!("\n=== Failed examples (first {}) ===", failed_examples.len());
        for ex in &failed_examples {
            eprintln!("{ex}");
        }
    }
}
