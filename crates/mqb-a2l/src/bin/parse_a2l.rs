use std::time::Instant;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let path = args
        .get(1)
        .map(|s| s.as_str())
        .unwrap_or("../../../a2l/SC8S5031_C_OEM.a2l");

    eprintln!("Reading {path}...");
    let t0 = Instant::now();
    let bytes = std::fs::read(path).expect("failed to read file");
    eprintln!(
        "  read {} MB in {:.2?}",
        bytes.len() / 1_048_576,
        t0.elapsed()
    );

    eprintln!("Parsing...");
    let t1 = Instant::now();
    let a2l = mqb_a2l::parse(&bytes).expect("parse failed");
    eprintln!("  parsed in {:.2?}", t1.elapsed());

    eprintln!(
        "  {} measurements, {} compu_methods, {} compu_vtabs, {} compu_vtab_ranges",
        a2l.measurements.len(),
        a2l.compu_methods.len(),
        a2l.compu_vtabs.len(),
        a2l.compu_vtab_ranges.len(),
    );
    eprintln!(
        "  {} characteristics, {} axis_pts, {} record_layouts",
        a2l.characteristics.len(),
        a2l.axis_pts.len(),
        a2l.record_layouts.len(),
    );

    // Count characteristic types
    let mut type_counts = std::collections::HashMap::new();
    for ch in &a2l.characteristics {
        *type_counts
            .entry(format!("{:?}", ch.char_type))
            .or_insert(0usize) += 1;
    }
    eprintln!("\nCharacteristic types:");
    for (typ, count) in &type_counts {
        eprintln!("  {typ:10} {count}");
    }

    // Count axis attributes
    let mut axis_counts = std::collections::HashMap::new();
    for ch in &a2l.characteristics {
        for ax in &ch.axes {
            *axis_counts
                .entry(format!("{:?}", ax.attribute))
                .or_insert(0usize) += 1;
        }
    }
    eprintln!("\nAxis types:");
    for (typ, count) in &axis_counts {
        eprintln!("  {typ:10} {count}");
    }

    // Functions
    let parent_count = a2l
        .functions
        .iter()
        .filter(|f| !f.sub_functions.is_empty())
        .count();
    let leaf_with_chars = a2l
        .functions
        .iter()
        .filter(|f| !f.def_characteristics.is_empty() || !f.ref_characteristics.is_empty())
        .count();
    eprintln!(
        "\nFunctions: {} total, {} parents (with SUB_FUNCTION), {} with characteristics",
        a2l.functions.len(),
        parent_count,
        leaf_with_chars
    );

    // Print first 5 parent functions
    eprintln!("\nFirst 5 parent functions:");
    for f in a2l
        .functions
        .iter()
        .filter(|f| !f.sub_functions.is_empty())
        .take(5)
    {
        eprintln!(
            "  {:30} {:50} subs={}",
            f.name,
            f.description,
            f.sub_functions.len()
        );
    }

    // Print first 5 characteristics
    eprintln!("\nFirst 5 characteristics:");
    for ch in a2l.characteristics.iter().take(5) {
        let cm = a2l.compu_methods.get(&ch.compu_method_ref);
        let unit = cm.map(|c| c.unit.as_str()).unwrap_or("?");
        eprintln!(
            "  {:40} {:8?} {:#010x} unit={:?} axes={}",
            ch.name,
            ch.char_type,
            ch.address,
            unit,
            ch.axes.len(),
        );
    }
}
