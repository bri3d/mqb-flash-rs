//! Read CHARACTERISTIC values from ECU binary data using A2L definitions.

use crate::types::*;
use mqb_bytes::*;

/// Address mapping entry: `(ecu_base_address, binary_file_offset, block_length)`.
pub type AddressMap = Vec<(u32, usize, usize)>;

/// Build an address-resolver closure from an [`AddressMap`].
pub fn make_resolver(map: &AddressMap) -> impl Fn(u32) -> Option<usize> + '_ {
    move |addr| {
        for &(base, file_off, len) in map {
            let offset = addr.wrapping_sub(base);
            if offset < len as u32 {
                return Some(file_off + offset as usize);
            }
        }
        None
    }
}

/// Values read from a CHARACTERISTIC in ECU memory.
#[derive(Debug, Clone, PartialEq)]
pub enum CharacteristicValues {
    Scalar(f64),
    Ascii(String),
    Curve {
        x: Vec<f64>,
        y: Vec<f64>,
    },
    Map {
        x: Vec<f64>,
        y: Vec<f64>,
        /// `z[y_idx][x_idx]` — row-major.
        z: Vec<Vec<f64>>,
    },
    /// 3D cuboid: `w[z_idx][y_idx][x_idx]`.
    Cuboid {
        x: Vec<f64>,
        y: Vec<f64>,
        z: Vec<f64>,
        w: Vec<Vec<Vec<f64>>>,
    },
    ValBlk(Vec<f64>),
}

/// Read a CHARACTERISTIC's values from binary data.
///
/// Returns `None` if the address cannot be resolved, the record layout is
/// missing, or the binary data is too short.
pub fn read_characteristic(
    ch: &Characteristic,
    a2l: &A2lFile,
    binary: &[u8],
    resolve_addr: &dyn Fn(u32) -> Option<usize>,
) -> Option<CharacteristicValues> {
    let layout = a2l.record_layouts.get(&ch.deposit)?;
    let base = resolve_addr(ch.address)?;

    match ch.char_type {
        CharacteristicType::Value => read_value(ch, layout, a2l, binary, base),
        CharacteristicType::Curve => read_curve(ch, layout, a2l, binary, base, resolve_addr),
        CharacteristicType::Map => read_map(ch, layout, a2l, binary, base, resolve_addr),
        CharacteristicType::ValBlk => read_val_blk(ch, layout, a2l, binary, base, resolve_addr),
        CharacteristicType::Ascii => read_ascii(layout, binary, base),
        CharacteristicType::Cuboid => read_cuboid(ch, layout, a2l, binary, base, resolve_addr),
        _ => None, // CUBE_4, CUBE_5 not yet supported
    }
}

// ── Scalar VALUE ────────────────────────────────────────────────────────────

fn read_value(
    ch: &Characteristic,
    layout: &RecordLayout,
    a2l: &A2lFile,
    binary: &[u8],
    base: usize,
) -> Option<CharacteristicValues> {
    let fnc = layout.fnc_values.as_ref()?;
    let raw = read_raw(binary, base, fnc.datatype)?;
    Some(CharacteristicValues::Scalar(apply_conv(
        raw,
        &ch.compu_method_ref,
        a2l,
    )))
}

// ── CURVE (1D) ──────────────────────────────────────────────────────────────

fn read_curve(
    ch: &Characteristic,
    layout: &RecordLayout,
    a2l: &A2lFile,
    binary: &[u8],
    base: usize,
    resolve_addr: &dyn Fn(u32) -> Option<usize>,
) -> Option<CharacteristicValues> {
    let axis = ch.axes.first()?;
    let fnc = layout.fnc_values.as_ref()?;

    let (x_phys, fnc_offset) = resolve_axis_x(axis, layout, a2l, binary, base, resolve_addr)?;
    let count = x_phys.len();

    let mut y = Vec::with_capacity(count);
    let mut off = base + fnc_offset;
    for _ in 0..count {
        y.push(apply_conv(
            read_raw(binary, off, fnc.datatype)?,
            &ch.compu_method_ref,
            a2l,
        ));
        off += fnc.datatype.byte_width();
    }

    Some(CharacteristicValues::Curve { x: x_phys, y })
}

// ── MAP (2D) ────────────────────────────────────────────────────────────────

fn read_map(
    ch: &Characteristic,
    layout: &RecordLayout,
    a2l: &A2lFile,
    binary: &[u8],
    base: usize,
    resolve_addr: &dyn Fn(u32) -> Option<usize>,
) -> Option<CharacteristicValues> {
    let axis_x = ch.axes.first()?;
    let axis_y = ch.axes.get(1)?;
    let fnc = layout.fnc_values.as_ref()?;

    // For maps with COM_AXIS on both: record layout has only FNC_VALUES.
    // For maps with STD_AXIS: record layout has inline axis data.
    let (x_phys, y_phys, fnc_offset) = if axis_x.attribute == AxisAttribute::ComAxis
        && axis_y.attribute == AxisAttribute::ComAxis
    {
        let x = read_com_axis(axis_x, a2l, binary, resolve_addr)?;
        let y = read_com_axis(axis_y, a2l, binary, resolve_addr)?;
        (x, y, 0usize)
    } else if axis_x.attribute == AxisAttribute::FixAxis
        && axis_y.attribute == AxisAttribute::FixAxis
    {
        let x = compute_fix_axis(axis_x)?;
        let y = compute_fix_axis(axis_y)?;
        (x, y, 0)
    } else {
        // Mixed or STD_AXIS — read inline
        let ir = read_inline(
            layout,
            binary,
            base,
            axis_x.max_axis_points as usize,
            axis_y.max_axis_points as usize,
        )?;
        let x = apply_conv_vec(&ir.x_values, &axis_x.compu_method_ref, a2l);
        let y = apply_conv_vec(&ir.y_values, &axis_y.compu_method_ref, a2l);
        (x, y, ir.fnc_offset)
    };

    let xn = x_phys.len();
    let yn = y_phys.len();

    // Read function values into flat array, then reshape
    let total = xn * yn;
    let w = fnc.datatype.byte_width();
    let mut flat = Vec::with_capacity(total);
    let mut off = base + fnc_offset;
    for _ in 0..total {
        flat.push(apply_conv(
            read_raw(binary, off, fnc.datatype)?,
            &ch.compu_method_ref,
            a2l,
        ));
        off += w;
    }

    let mut z = Vec::with_capacity(yn);
    for yi in 0..yn {
        let row: Vec<f64> = if fnc.column_dir {
            // COLUMN_DIR: column-major, Y varies fastest → data[y + x * yn]
            (0..xn).map(|xi| flat[yi + xi * yn]).collect()
        } else {
            // ROW_DIR: row-major, X varies fastest → data[x + y * xn]
            (0..xn).map(|xi| flat[xi + yi * xn]).collect()
        };
        z.push(row);
    }

    Some(CharacteristicValues::Map {
        x: x_phys,
        y: y_phys,
        z,
    })
}

// ── CUBOID (3D) ─────────────────────────────────────────────────────────

fn read_cuboid(
    ch: &Characteristic,
    layout: &RecordLayout,
    a2l: &A2lFile,
    binary: &[u8],
    base: usize,
    resolve_addr: &dyn Fn(u32) -> Option<usize>,
) -> Option<CharacteristicValues> {
    let axis_x = ch.axes.first()?;
    let axis_y = ch.axes.get(1)?;
    let axis_z = ch.axes.get(2)?;
    let fnc = layout.fnc_values.as_ref()?;

    // Resolve all three axes (COM_AXIS or FIX_AXIS)
    let x_phys = resolve_axis_values(axis_x, a2l, binary, resolve_addr)?;
    let y_phys = resolve_axis_values(axis_y, a2l, binary, resolve_addr)?;
    let z_phys = resolve_axis_values(axis_z, a2l, binary, resolve_addr)?;

    let xn = x_phys.len();
    let yn = y_phys.len();
    let zn = z_phys.len();
    let total = xn * yn * zn;
    let w = fnc.datatype.byte_width();

    // Read all function values flat
    let mut flat = Vec::with_capacity(total);
    let mut off = base;
    for _ in 0..total {
        flat.push(apply_conv(
            read_raw(binary, off, fnc.datatype)?,
            &ch.compu_method_ref,
            a2l,
        ));
        off += w;
    }

    // Reshape into w[z][y][x] — Z slices stored sequentially, within each
    // slice COLUMN_DIR/ROW_DIR determines 2D layout.
    let mut result = Vec::with_capacity(zn);
    if fnc.column_dir {
        // COLUMN_DIR: column-major per slice, Y varies fastest
        for zi in 0..zn {
            let mut slice = Vec::with_capacity(yn);
            for yi in 0..yn {
                let row: Vec<f64> = (0..xn)
                    .map(|xi| flat[yi + xi * yn + zi * xn * yn])
                    .collect();
                slice.push(row);
            }
            result.push(slice);
        }
    } else {
        // ROW_DIR: row-major per slice, X varies fastest
        for zi in 0..zn {
            let mut slice = Vec::with_capacity(yn);
            for yi in 0..yn {
                let row: Vec<f64> = (0..xn)
                    .map(|xi| flat[xi + yi * xn + zi * xn * yn])
                    .collect();
                slice.push(row);
            }
            result.push(slice);
        }
    }

    Some(CharacteristicValues::Cuboid {
        x: x_phys,
        y: y_phys,
        z: z_phys,
        w: result,
    })
}

/// Resolve axis values for COM_AXIS or FIX_AXIS (no inline support).
fn resolve_axis_values(
    axis: &AxisDescr,
    a2l: &A2lFile,
    binary: &[u8],
    resolve_addr: &dyn Fn(u32) -> Option<usize>,
) -> Option<Vec<f64>> {
    match axis.attribute {
        AxisAttribute::ComAxis => read_com_axis(axis, a2l, binary, resolve_addr),
        AxisAttribute::FixAxis => compute_fix_axis(axis),
        _ => None,
    }
}

// ── VAL_BLK ─────────────────────────────────────────────────────────────────

fn read_val_blk(
    ch: &Characteristic,
    layout: &RecordLayout,
    a2l: &A2lFile,
    binary: &[u8],
    base: usize,
    resolve_addr: &dyn Fn(u32) -> Option<usize>,
) -> Option<CharacteristicValues> {
    let fnc = layout.fnc_values.as_ref()?;

    // Determine count from axes or record layout
    let count = if let Some(axis) = ch.axes.first() {
        match axis.attribute {
            AxisAttribute::FixAxis => {
                if let Some(list) = &axis.fix_axis_par_list {
                    list.len()
                } else {
                    axis.fix_axis_par_dist
                        .as_ref()
                        .map(|d| d.count as usize)
                        .unwrap_or(axis.max_axis_points as usize)
                }
            }
            AxisAttribute::ComAxis => {
                let x = read_com_axis(axis, a2l, binary, resolve_addr)?;
                x.len()
            }
            _ => axis.max_axis_points as usize,
        }
    } else if let Some(n) = layout.fix_no_axis_pts_x {
        n as usize
    } else {
        1
    };

    let mut vals = Vec::with_capacity(count);
    let mut off = base;
    for _ in 0..count {
        vals.push(apply_conv(
            read_raw(binary, off, fnc.datatype)?,
            &ch.compu_method_ref,
            a2l,
        ));
        off += fnc.datatype.byte_width();
    }

    Some(CharacteristicValues::ValBlk(vals))
}

// ── ASCII ───────────────────────────────────────────────────────────────────

fn read_ascii(layout: &RecordLayout, binary: &[u8], base: usize) -> Option<CharacteristicValues> {
    // ASCII characteristics typically use a fixed number of bytes.
    // Without an explicit count, try the fix_no_axis_pts_x or use a reasonable max.
    let count = layout
        .fix_no_axis_pts_x
        .or_else(|| layout.fnc_values.as_ref().map(|_| 32))
        .unwrap_or(32) as usize;
    let end = (base + count).min(binary.len());
    if base >= binary.len() {
        return None;
    }
    let bytes = &binary[base..end];
    // Trim null bytes and decode as Latin-1
    let trimmed = bytes.split(|&b| b == 0).next().unwrap_or(bytes);
    let s: String = trimmed.iter().map(|&b| b as char).collect();
    Some(CharacteristicValues::Ascii(s))
}

// ── Axis resolution helpers ─────────────────────────────────────────────────

/// Resolve the X axis for a CURVE — returns (physical_values, byte_offset_of_fnc_values).
fn resolve_axis_x(
    axis: &AxisDescr,
    layout: &RecordLayout,
    a2l: &A2lFile,
    binary: &[u8],
    base: usize,
    resolve_addr: &dyn Fn(u32) -> Option<usize>,
) -> Option<(Vec<f64>, usize)> {
    match axis.attribute {
        AxisAttribute::ComAxis => {
            let x = read_com_axis(axis, a2l, binary, resolve_addr)?;
            Some((x, 0)) // FNC_VALUES at base for COM_AXIS layouts
        }
        AxisAttribute::StdAxis => {
            let ir = read_inline(layout, binary, base, axis.max_axis_points as usize, 0)?;
            let x = apply_conv_vec(&ir.x_values, &axis.compu_method_ref, a2l);
            Some((x, ir.fnc_offset))
        }
        AxisAttribute::FixAxis => {
            let x = compute_fix_axis(axis)?;
            Some((x, 0))
        }
        _ => None,
    }
}

/// Read axis values from a shared AXIS_PTS object (COM_AXIS).
fn read_com_axis(
    axis: &AxisDescr,
    a2l: &A2lFile,
    binary: &[u8],
    resolve_addr: &dyn Fn(u32) -> Option<usize>,
) -> Option<Vec<f64>> {
    let pts_name = axis.axis_pts_ref.as_ref()?;
    let pts = a2l.axis_pts.get(pts_name)?;
    let pts_layout = a2l.record_layouts.get(&pts.deposit)?;
    let pts_base = resolve_addr(pts.address)?;

    let mut offset = 0usize;
    let mut count = pts.max_axis_points as usize;

    // Read count if layout has NO_AXIS_PTS_X
    if let Some(nap) = &pts_layout.no_axis_pts_x {
        count = read_raw(binary, pts_base + offset, nap.datatype)? as usize;
        offset += nap.datatype.byte_width();
    }

    // Read axis values
    let dt = pts_layout
        .axis_pts_x
        .as_ref()
        .map(|f| f.datatype)
        .or_else(|| pts_layout.fnc_values.as_ref().map(|f| f.datatype))?;

    let mut raw_vals = Vec::with_capacity(count);
    for _ in 0..count {
        raw_vals.push(read_raw(binary, pts_base + offset, dt)?);
        offset += dt.byte_width();
    }

    Some(apply_conv_vec(&raw_vals, &pts.compu_method_ref, a2l))
}

/// Compute axis values from FIX_AXIS_PAR_DIST or FIX_AXIS_PAR_LIST.
fn compute_fix_axis(axis: &AxisDescr) -> Option<Vec<f64>> {
    if let Some(list) = &axis.fix_axis_par_list {
        return Some(list.clone());
    }
    let dist = axis.fix_axis_par_dist.as_ref()?;
    let vals: Vec<f64> = (0..dist.count as usize)
        .map(|i| dist.offset + dist.distance * i as f64)
        .collect();
    Some(vals)
}

// ── Inline layout reader (for STD_AXIS) ─────────────────────────────────────

struct InlineResult {
    x_values: Vec<f64>,
    y_values: Vec<f64>,
    fnc_offset: usize,
}

/// Read inline axis data from a record layout with embedded axis fields.
fn read_inline(
    layout: &RecordLayout,
    binary: &[u8],
    base: usize,
    default_x: usize,
    default_y: usize,
) -> Option<InlineResult> {
    #[derive(Clone, Copy)]
    enum Tag {
        NapX,
        ApX,
        NapY,
        ApY,
        Fnc,
    }

    let mut fields: Vec<(u16, Tag, DataType)> = Vec::new();
    if let Some(f) = &layout.no_axis_pts_x {
        fields.push((f.position, Tag::NapX, f.datatype));
    }
    if let Some(f) = &layout.axis_pts_x {
        fields.push((f.position, Tag::ApX, f.datatype));
    }
    if let Some(f) = &layout.no_axis_pts_y {
        fields.push((f.position, Tag::NapY, f.datatype));
    }
    if let Some(f) = &layout.axis_pts_y {
        fields.push((f.position, Tag::ApY, f.datatype));
    }
    if let Some(f) = &layout.fnc_values {
        fields.push((f.position, Tag::Fnc, f.datatype));
    }
    fields.sort_by_key(|f| f.0);

    let mut offset = 0usize;
    let mut x_count = default_x;
    let mut y_count = default_y;
    let mut x_values = Vec::new();
    let mut y_values = Vec::new();
    let mut fnc_offset = 0;

    for &(_, tag, dt) in &fields {
        let w = dt.byte_width();
        match tag {
            Tag::NapX => {
                x_count = read_raw(binary, base + offset, dt)? as usize;
                offset += w;
            }
            Tag::ApX => {
                for _ in 0..x_count {
                    x_values.push(read_raw(binary, base + offset, dt)?);
                    offset += w;
                }
            }
            Tag::NapY => {
                y_count = read_raw(binary, base + offset, dt)? as usize;
                offset += w;
            }
            Tag::ApY => {
                for _ in 0..y_count {
                    y_values.push(read_raw(binary, base + offset, dt)?);
                    offset += w;
                }
            }
            Tag::Fnc => {
                fnc_offset = offset;
            }
        }
    }

    Some(InlineResult {
        x_values,
        y_values,
        fnc_offset,
    })
}

// ── Raw value reading ───────────────────────────────────────────────────────

fn read_raw(data: &[u8], offset: usize, dt: DataType) -> Option<f64> {
    let w = dt.byte_width();
    if offset + w > data.len() {
        return None;
    }
    Some(match dt {
        DataType::UByte => data[offset] as f64,
        DataType::SByte => data[offset] as i8 as f64,
        DataType::UWord => read_u16_le(data, offset) as f64,
        DataType::SWord => read_i16_le(data, offset) as f64,
        DataType::ULong => read_u32_le(data, offset) as f64,
        DataType::SLong => read_i32_le(data, offset) as f64,
        DataType::Float32Ieee => read_f32_le(data, offset) as f64,
        DataType::Float64Ieee => read_f64_le(data, offset),
        DataType::AUint64 => read_u64_le(data, offset) as f64,
        DataType::AInt64 => read_i64_le(data, offset) as f64,
    })
}

// ── Conversion helpers ──────────────────────────────────────────────────────

fn apply_conv(raw: f64, cm_ref: &str, a2l: &A2lFile) -> f64 {
    if cm_ref == "NO_COMPU_METHOD" {
        return raw;
    }
    if let Some(cm) = a2l.compu_methods.get(cm_ref) {
        cm.conversion.to_physical(raw).unwrap_or(raw)
    } else {
        raw
    }
}

fn apply_conv_vec(raw: &[f64], cm_ref: &str, a2l: &A2lFile) -> Vec<f64> {
    raw.iter().map(|v| apply_conv(*v, cm_ref, a2l)).collect()
}
