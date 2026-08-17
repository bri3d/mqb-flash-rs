mod error;
mod lexer;
mod parser;
pub mod reader;
pub mod types;

pub use error::{Error, Result};
pub use types::*;

/// Parse an A2L file from raw bytes (Latin-1 / Windows-1252 encoded is fine).
pub fn parse(src: &[u8]) -> Result<A2lFile> {
    parser::parse(src)
}

/// Convenience: read an A2L file from disk and parse it.
pub fn parse_file(path: &std::path::Path) -> Result<A2lFile> {
    let bytes = std::fs::read(path)?;
    parse(&bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &[u8] = br#"
/* header comment */
/begin PROJECT SC8
  /begin MODULE ENGINE
    /begin MEASUREMENT rpm
      "Engine speed"
      UWORD
      RPM_CM
      1
      100.
      0.
      8000.
      ECU_ADDRESS 0x40001234
      /begin IF_DATA ETK
        KP_BLOB 0x40001234 INTERN 2 RASTER 10
      /end IF_DATA
    /end MEASUREMENT

    /begin MEASUREMENT flags
      "Status flags"
      UBYTE
      STATUS_CM
      1
      100.
      0.
      255.
      ECU_ADDRESS 0x40001236
      BIT_MASK 0x0F
    /end MEASUREMENT

    /begin COMPU_METHOD RPM_CM
      "RPM conversion"
      RAT_FUNC
      "%6.1"
      "rpm"
      COEFFS 0 4 0 0 0 1
    /end COMPU_METHOD

    /begin COMPU_METHOD STATUS_CM
      "Status verbal"
      TAB_VERB
      "%d"
      "-"
      COMPU_TAB_REF STATUS_TAB
    /end COMPU_METHOD

    /begin COMPU_VTAB STATUS_TAB
      "Status table"
      TAB_VERB
      3
      0 "Off"
      1 "On"
      2 "Error"
    /end COMPU_VTAB
  /end MODULE
/end PROJECT
"#;

    #[test]
    fn parse_sample() {
        let a2l = parse(SAMPLE).unwrap();

        assert_eq!(a2l.measurements.len(), 2);
        assert_eq!(a2l.compu_methods.len(), 2);
        assert_eq!(a2l.compu_vtabs.len(), 1);

        let rpm = a2l.measurements.iter().find(|m| m.name == "rpm").unwrap();
        assert_eq!(rpm.ecu_address, Some(0x40001234));
        assert_eq!(rpm.datatype, DataType::UWord);
        assert_eq!(rpm.compu_method_ref, "RPM_CM");
        assert_eq!(rpm.bit_mask, None);

        let flags = a2l.measurements.iter().find(|m| m.name == "flags").unwrap();
        assert_eq!(flags.bit_mask, Some(0x0F));

        let cm = a2l.compu_methods.get("RPM_CM").unwrap();
        assert_eq!(cm.unit, "rpm");
        // COEFFS 0 4 0 0 0 1 → internal = 4·phys → phys = internal/4
        let phys = cm.conversion.to_physical(1000.0).unwrap();
        assert!((phys - 250.0).abs() < 1e-9, "phys={phys}");

        let vtab = a2l.compu_vtabs.get("STATUS_TAB").unwrap();
        assert_eq!(vtab.lookup(1), Some("On"));
        assert_eq!(vtab.lookup(99), None);
    }

    const CHAR_SAMPLE: &[u8] = br#"
/begin PROJECT SC8
  /begin MODULE ENGINE

    /begin COMPU_METHOD LINEAR_CM "" RAT_FUNC "%6.3" "kPa"
      COEFFS 0 128. 0. 0 0 1
    /end COMPU_METHOD

    /begin COMPU_METHOD AXIS_CM "" RAT_FUNC "%4.1" "rpm"
      COEFFS 0 32. 0. 0 0 1
    /end COMPU_METHOD

    /begin RECORD_LAYOUT VAL_U2
      FNC_VALUES 1 UWORD COLUMN_DIR DIRECT
    /end RECORD_LAYOUT

    /begin RECORD_LAYOUT CUR_U1_U2
      FNC_VALUES 1 UBYTE COLUMN_DIR DIRECT
    /end RECORD_LAYOUT

    /begin RECORD_LAYOUT AXS_U1
      NO_AXIS_PTS_X 1 UBYTE
      AXIS_PTS_X 2 UBYTE INDEX_INCR DIRECT
    /end RECORD_LAYOUT

    /begin RECORD_LAYOUT STD_CUR
      NO_AXIS_PTS_X 1 UBYTE
      AXIS_PTS_X 2 UWORD INDEX_INCR DIRECT
      FNC_VALUES 3 UBYTE COLUMN_DIR DIRECT
    /end RECORD_LAYOUT

    /begin AXIS_PTS shared_axis "" 0x100 NO_INPUT_QUANTITY AXS_U1
      255. AXIS_CM 4 0. 255.
    /end AXIS_PTS

    /begin CHARACTERISTIC scalar_val
      "A scalar value"
      VALUE
      0x200
      VAL_U2
      1.0
      LINEAR_CM
      0.
      1000.
      FORMAT "%6.3"
    /end CHARACTERISTIC

    /begin CHARACTERISTIC my_curve
      "A 1D curve with COM_AXIS"
      CURVE
      0x300
      CUR_U1_U2
      255.
      LINEAR_CM
      0.
      1000.
      /begin AXIS_DESCR
        COM_AXIS
        NO_INPUT_QUANTITY
        AXIS_CM
        4
        0.
        255.
        AXIS_PTS_REF shared_axis
      /end AXIS_DESCR
    /end CHARACTERISTIC

    /begin CHARACTERISTIC std_curve
      "A 1D curve with STD_AXIS"
      CURVE
      0x400
      STD_CUR
      255.
      LINEAR_CM
      0.
      1000.
      /begin AXIS_DESCR
        STD_AXIS
        NO_INPUT_QUANTITY
        AXIS_CM
        8
        0.
        65535.
      /end AXIS_DESCR
    /end CHARACTERISTIC

    /begin CHARACTERISTIC fix_blk
      "A VAL_BLK with FIX_AXIS"
      VAL_BLK
      0x500
      VAL_U2
      255.
      LINEAR_CM
      0.
      1000.
      /begin AXIS_DESCR
        FIX_AXIS
        NO_INPUT_QUANTITY
        NO_COMPU_METHOD
        3
        0.
        2.
        FIX_AXIS_PAR_DIST 0 1 3
      /end AXIS_DESCR
    /end CHARACTERISTIC

  /end MODULE
/end PROJECT
"#;

    #[test]
    fn parse_characteristics() {
        let a2l = parse(CHAR_SAMPLE).unwrap();

        // Check counts
        assert_eq!(a2l.characteristics.len(), 4);
        assert_eq!(a2l.axis_pts.len(), 1);
        assert_eq!(a2l.record_layouts.len(), 4);

        // Scalar VALUE
        let scalar = a2l
            .characteristics
            .iter()
            .find(|c| c.name == "scalar_val")
            .unwrap();
        assert_eq!(scalar.char_type, CharacteristicType::Value);
        assert_eq!(scalar.address, 0x200);
        assert_eq!(scalar.deposit, "VAL_U2");
        assert_eq!(scalar.compu_method_ref, "LINEAR_CM");
        assert_eq!(scalar.format.as_deref(), Some("%6.3"));
        assert!(scalar.axes.is_empty());

        // CURVE with COM_AXIS
        let curve = a2l
            .characteristics
            .iter()
            .find(|c| c.name == "my_curve")
            .unwrap();
        assert_eq!(curve.char_type, CharacteristicType::Curve);
        assert_eq!(curve.axes.len(), 1);
        assert_eq!(curve.axes[0].attribute, AxisAttribute::ComAxis);
        assert_eq!(curve.axes[0].axis_pts_ref.as_deref(), Some("shared_axis"));

        // CURVE with STD_AXIS
        let std_cur = a2l
            .characteristics
            .iter()
            .find(|c| c.name == "std_curve")
            .unwrap();
        assert_eq!(std_cur.axes[0].attribute, AxisAttribute::StdAxis);

        // AXIS_PTS
        let axis = a2l.axis_pts.get("shared_axis").unwrap();
        assert_eq!(axis.address, 0x100);
        assert_eq!(axis.max_axis_points, 4);

        // RECORD_LAYOUT
        let rl = a2l.record_layouts.get("STD_CUR").unwrap();
        assert!(rl.no_axis_pts_x.is_some());
        assert!(rl.axis_pts_x.is_some());
        assert!(rl.fnc_values.is_some());
        assert_eq!(rl.fnc_values.as_ref().unwrap().position, 3);

        // VAL_BLK with FIX_AXIS
        let blk = a2l
            .characteristics
            .iter()
            .find(|c| c.name == "fix_blk")
            .unwrap();
        assert_eq!(blk.char_type, CharacteristicType::ValBlk);
        assert_eq!(blk.axes[0].attribute, AxisAttribute::FixAxis);
        let dist = blk.axes[0].fix_axis_par_dist.as_ref().unwrap();
        assert_eq!(dist.count, 3);
    }

    #[test]
    fn read_characteristic_values() {
        use crate::reader::*;

        let a2l = parse(CHAR_SAMPLE).unwrap();

        // Build a fake binary:
        // Address map: everything maps 1:1 (base=0, offset=0, len=big)
        let map: AddressMap = vec![(0, 0, 0x10000)];
        let resolve = make_resolver(&map);

        let mut binary = vec![0u8; 0x10000];

        // scalar_val at 0x200: UWORD = 256 → physical = (1 * 256 - 0) / 128 = 2.0
        binary[0x200] = 0x00;
        binary[0x201] = 0x01; // 256 LE

        // shared_axis at 0x100: AXS_U1 = [count=4] [32, 64, 96, 128]
        binary[0x100] = 4;
        binary[0x101] = 32;
        binary[0x102] = 64;
        binary[0x103] = 96;
        binary[0x104] = 128;

        // my_curve at 0x300: CUR_U1_U2 FNC_VALUES = 4 UBYTEs [10, 20, 30, 40]
        binary[0x300] = 10;
        binary[0x301] = 20;
        binary[0x302] = 30;
        binary[0x303] = 40;

        // std_curve at 0x400: STD_CUR
        //   NO_AXIS_PTS_X = 3 (UBYTE)
        //   AXIS_PTS_X = [100, 200, 300] (3 UWORDs = 6 bytes)
        //   FNC_VALUES = [50, 60, 70] (3 UBYTEs)
        binary[0x400] = 3; // count
        binary[0x401..0x403].copy_from_slice(&100u16.to_le_bytes());
        binary[0x403..0x405].copy_from_slice(&200u16.to_le_bytes());
        binary[0x405..0x407].copy_from_slice(&300u16.to_le_bytes());
        binary[0x407] = 50;
        binary[0x408] = 60;
        binary[0x409] = 70;

        // fix_blk at 0x500: 3 UWORDs [1000, 2000, 3000]
        binary[0x500..0x502].copy_from_slice(&1000u16.to_le_bytes());
        binary[0x502..0x504].copy_from_slice(&2000u16.to_le_bytes());
        binary[0x504..0x506].copy_from_slice(&3000u16.to_le_bytes());

        // Test scalar
        let ch = a2l
            .characteristics
            .iter()
            .find(|c| c.name == "scalar_val")
            .unwrap();
        let val = read_characteristic(ch, &a2l, &binary, &resolve).unwrap();
        match val {
            CharacteristicValues::Scalar(v) => {
                // COEFFS 0 128 0 0 0 1 → phys = (1 * raw - 0) / 128 = raw / 128
                assert!((v - 2.0).abs() < 1e-9, "scalar: {v}");
            }
            _ => panic!("expected Scalar"),
        }

        // Test COM_AXIS curve
        let ch = a2l
            .characteristics
            .iter()
            .find(|c| c.name == "my_curve")
            .unwrap();
        let val = read_characteristic(ch, &a2l, &binary, &resolve).unwrap();
        match val {
            CharacteristicValues::Curve { x, y } => {
                assert_eq!(x.len(), 4);
                assert_eq!(y.len(), 4);
                // axis: 32/32=1.0, 64/32=2.0, 96/32=3.0, 128/32=4.0
                assert!((x[0] - 1.0).abs() < 1e-9);
                assert!((x[3] - 4.0).abs() < 1e-9);
                // values: 10/128, 20/128, ...
                assert!((y[0] - 10.0 / 128.0).abs() < 1e-9);
            }
            _ => panic!("expected Curve"),
        }

        // Test STD_AXIS curve
        let ch = a2l
            .characteristics
            .iter()
            .find(|c| c.name == "std_curve")
            .unwrap();
        let val = read_characteristic(ch, &a2l, &binary, &resolve).unwrap();
        match val {
            CharacteristicValues::Curve { x, y } => {
                assert_eq!(x.len(), 3);
                assert_eq!(y.len(), 3);
                // axis: 100/32=3.125, 200/32=6.25, 300/32=9.375
                assert!((x[0] - 3.125).abs() < 1e-9);
                // values: 50/128, 60/128, 70/128
                assert!((y[0] - 50.0 / 128.0).abs() < 1e-9);
            }
            _ => panic!("expected Curve"),
        }

        // Test FIX_AXIS VAL_BLK
        let ch = a2l
            .characteristics
            .iter()
            .find(|c| c.name == "fix_blk")
            .unwrap();
        let val = read_characteristic(ch, &a2l, &binary, &resolve).unwrap();
        match val {
            CharacteristicValues::ValBlk(v) => {
                assert_eq!(v.len(), 3);
                // 1000/128 ≈ 7.8125
                assert!((v[0] - 1000.0 / 128.0).abs() < 1e-9);
            }
            _ => panic!("expected ValBlk"),
        }
    }
}
