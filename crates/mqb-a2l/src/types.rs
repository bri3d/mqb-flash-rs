use std::collections::HashMap;

/// Parsed contents of an A2L file.
#[derive(Debug, Default)]
pub struct A2lFile {
    pub measurements: Vec<Measurement>,
    pub characteristics: Vec<Characteristic>,
    pub axis_pts: HashMap<String, AxisPts>,
    pub record_layouts: HashMap<String, RecordLayout>,
    pub compu_methods: HashMap<String, CompuMethod>,
    pub compu_vtabs: HashMap<String, CompuVtab>,
    pub compu_vtab_ranges: HashMap<String, CompuVtabRange>,
    pub functions: Vec<Function>,
}

// ── MEASUREMENT ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct Measurement {
    pub name: String,
    pub description: String,
    pub datatype: DataType,
    /// Name of the associated `COMPU_METHOD` (may be `"NO_COMPU_METHOD"`).
    pub compu_method_ref: String,
    pub ecu_address: Option<u32>,
    pub bit_mask: Option<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DataType {
    UByte,
    SByte,
    UWord,
    SWord,
    ULong,
    SLong,
    AUint64,
    AInt64,
    Float32Ieee,
    Float64Ieee,
}

impl DataType {
    pub fn byte_width(self) -> usize {
        match self {
            DataType::UByte | DataType::SByte => 1,
            DataType::UWord | DataType::SWord => 2,
            DataType::ULong | DataType::SLong | DataType::Float32Ieee => 4,
            DataType::AUint64 | DataType::AInt64 | DataType::Float64Ieee => 8,
        }
    }
}

// ── COMPU_METHOD ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct CompuMethod {
    pub name: String,
    pub description: String,
    pub format: String,
    pub unit: String,
    pub conversion: Conversion,
}

/// Conversion formula for a `COMPU_METHOD`.
#[derive(Debug, Clone)]
pub enum Conversion {
    /// `IDENTICAL` — no conversion; physical = internal.
    Identical,

    /// `RAT_FUNC` with `COEFFS a b c d e f`:
    ///   `internal = (a·phys² + b·phys + c) / (d·phys² + e·phys + f)`
    ///
    /// To convert *from* internal to physical, use [`rat_func_to_physical`].
    RatFunc { a: f64, b: f64, c: f64, d: f64, e: f64, f: f64 },

    /// `LINEAR` with `COEFFS_LINEAR a b`:
    ///   `physical = a·internal + b`
    Linear { a: f64, b: f64 },

    /// `TAB_VERB` — verbal (string) lookup table.
    TabVerb { tab_ref: String },

    /// `FORM` — arbitrary formula string.
    Form { formula: String },

    /// Other / unrecognised conversion type (stored as the type keyword).
    Other(String),
}

impl Conversion {
    /// Convert a raw ECU value to physical units.
    ///
    /// For `RatFunc` this inverts the formula assuming the common linear case
    /// (`a = 0`, `d = 0`):
    ///   `phys = (f·internal − c) / b`
    ///
    /// Returns `None` if the conversion type is verbal or unsupported for
    /// numeric inversion.
    pub fn to_physical(&self, internal: f64) -> Option<f64> {
        match self {
            Conversion::Identical => Some(internal),
            Conversion::Linear { a, b } => Some(a * internal + b),
            Conversion::RatFunc { a, b, c, d, e, f } => {
                // General case: internal = (a·p² + b·p + c) / (d·p² + e·p + f)
                // For the dominant linear case (a=0, d=0, e=0):
                //   internal = (b·p + c) / f  →  p = (f·internal - c) / b
                if *a == 0.0 && *d == 0.0 && *e == 0.0 && *b != 0.0 {
                    Some((f * internal - c) / b)
                } else {
                    // Fall back to numerical identity for unsupported shapes.
                    None
                }
            }
            Conversion::TabVerb { .. } | Conversion::Form { .. } | Conversion::Other(_) => None,
        }
    }

    /// For TAB_VERB: look up the verbal label for an internal integer value.
    /// The lookup is performed on `compu_vtabs` passed in.
    pub fn to_verbal<'a>(
        &'a self,
        internal: i64,
        vtabs: &'a std::collections::HashMap<String, CompuVtab>,
    ) -> Option<&'a str> {
        if let Conversion::TabVerb { tab_ref } = self {
            vtabs.get(tab_ref)?.lookup(internal)
        } else {
            None
        }
    }
}

// ── COMPU_VTAB ───────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct CompuVtab {
    pub name: String,
    pub entries: Vec<(i64, String)>, // (internal_value, label)
}

impl CompuVtab {
    pub fn lookup(&self, internal: i64) -> Option<&str> {
        self.entries
            .iter()
            .find(|(k, _)| *k == internal)
            .map(|(_, v)| v.as_str())
    }
}

// ── COMPU_VTAB_RANGE ─────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct CompuVtabRange {
    pub name: String,
    /// Each entry: (inclusive_min, inclusive_max, label).
    pub entries: Vec<(i64, i64, String)>,
    pub default_label: Option<String>,
}

impl CompuVtabRange {
    pub fn lookup(&self, internal: i64) -> Option<&str> {
        for (lo, hi, label) in &self.entries {
            if internal >= *lo && internal <= *hi {
                return Some(label.as_str());
            }
        }
        self.default_label.as_deref()
    }
}

// ── CHARACTERISTIC ──────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CharacteristicType {
    Value,
    Curve,
    Map,
    Cuboid,
    Cube4,
    Cube5,
    ValBlk,
    Ascii,
}

#[derive(Debug, Clone)]
pub struct Characteristic {
    pub name: String,
    pub description: String,
    pub char_type: CharacteristicType,
    pub address: u32,
    /// Reference to the `RECORD_LAYOUT` name.
    pub deposit: String,
    pub max_diff: f64,
    /// Reference to the `COMPU_METHOD` name (or `"NO_COMPU_METHOD"`).
    pub compu_method_ref: String,
    pub lower_limit: f64,
    pub upper_limit: f64,
    /// Axis descriptors (0 for VALUE, 1 for CURVE, 2 for MAP, etc.).
    pub axes: Vec<AxisDescr>,
    pub format: Option<String>,
    pub display_identifier: Option<String>,
}

// ── AXIS_DESCR ──────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AxisAttribute {
    StdAxis,
    ComAxis,
    FixAxis,
    CurveAxis,
    ResAxis,
}

#[derive(Debug, Clone)]
pub struct AxisDescr {
    pub attribute: AxisAttribute,
    /// Reference to a MEASUREMENT, or `"NO_INPUT_QUANTITY"`.
    pub input_quantity: String,
    /// Reference to a COMPU_METHOD, or `"NO_COMPU_METHOD"`.
    pub compu_method_ref: String,
    pub max_axis_points: u16,
    pub lower_limit: f64,
    pub upper_limit: f64,
    /// Reference to an AXIS_PTS (for COM_AXIS).
    pub axis_pts_ref: Option<String>,
    /// Fixed axis distribution (for FIX_AXIS).
    pub fix_axis_par_dist: Option<FixAxisParDist>,
    /// Fixed axis explicit values (for FIX_AXIS with FIX_AXIS_PAR_LIST).
    pub fix_axis_par_list: Option<Vec<f64>>,
    pub format: Option<String>,
}

#[derive(Debug, Clone)]
pub struct FixAxisParDist {
    pub offset: f64,
    pub distance: f64,
    pub count: u16,
}

// ── AXIS_PTS ────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct AxisPts {
    pub name: String,
    pub description: String,
    pub address: u32,
    /// Reference to a MEASUREMENT, or `"NO_INPUT_QUANTITY"`.
    pub input_quantity: String,
    /// Reference to the RECORD_LAYOUT name.
    pub deposit: String,
    pub max_diff: f64,
    /// Reference to a COMPU_METHOD, or `"NO_COMPU_METHOD"`.
    pub compu_method_ref: String,
    pub max_axis_points: u16,
    pub lower_limit: f64,
    pub upper_limit: f64,
    pub format: Option<String>,
}

// ── RECORD_LAYOUT ───────────────────────────────────────────────────────────

#[derive(Debug, Clone, Default)]
pub struct RecordLayout {
    pub name: String,
    pub fnc_values: Option<FncValuesField>,
    pub axis_pts_x: Option<LayoutField>,
    pub axis_pts_y: Option<LayoutField>,
    pub no_axis_pts_x: Option<LayoutField>,
    pub no_axis_pts_y: Option<LayoutField>,
    pub axis_pts_z: Option<LayoutField>,
    pub no_axis_pts_z: Option<LayoutField>,
    pub fix_no_axis_pts_x: Option<u16>,
    pub fix_no_axis_pts_y: Option<u16>,
    pub fix_no_axis_pts_z: Option<u16>,
}

/// FNC_VALUES field in a RECORD_LAYOUT.
#[derive(Debug, Clone)]
pub struct FncValuesField {
    pub position: u16,
    pub datatype: DataType,
    /// `true` = COLUMN_DIR (column-major), `false` = ROW_DIR (row-major).
    pub column_dir: bool,
}

/// Axis or count field in a RECORD_LAYOUT.
#[derive(Debug, Clone)]
pub struct LayoutField {
    pub position: u16,
    pub datatype: DataType,
}

// ── FUNCTION ────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct Function {
    pub name: String,
    pub description: String,
    /// Characteristics defined by this function (DEF_CHARACTERISTIC).
    pub def_characteristics: Vec<String>,
    /// Characteristics referenced by this function (REF_CHARACTERISTIC).
    pub ref_characteristics: Vec<String>,
    /// Child function names (SUB_FUNCTION).
    pub sub_functions: Vec<String>,
}
