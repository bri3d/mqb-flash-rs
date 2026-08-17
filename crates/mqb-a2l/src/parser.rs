use crate::error::{Error, Result};
use crate::lexer::{Lexer, Token};
use crate::types::*;

pub fn parse(src: &[u8]) -> Result<A2lFile> {
    let mut lex = Lexer::new(src);
    let mut file = A2lFile::default();
    parse_block_contents(&mut lex, &mut file, None)?;
    Ok(file)
}

/// Parse the content of a block (or the top level when `end_kw` is `None`).
/// Recurses into any unknown sub-block so that MEASUREMENT / COMPU_METHOD /
/// COMPU_VTAB / COMPU_VTAB_RANGE are found at any nesting depth.
fn parse_block_contents(
    lex: &mut Lexer<'_>,
    file: &mut A2lFile,
    end_kw: Option<&str>,
) -> Result<()> {
    loop {
        match lex.next_token() {
            None => {
                if end_kw.is_some() {
                    return Err(Error::UnexpectedEof);
                }
                return Ok(());
            }
            Some(tok) if tok.eq_word("/end") => {
                let kw = expect_word(lex)?;
                if let Some(expected) = end_kw {
                    if kw != expected {
                        return Err(Error::UnexpectedKeyword {
                            expected: expected.to_string(),
                            got: kw,
                        });
                    }
                    return Ok(());
                }
                // Stray /end at top level — ignore and keep going.
            }
            Some(tok) if tok.eq_word("/begin") => {
                let kw = expect_word(lex)?;
                match kw.as_str() {
                    "MEASUREMENT" => {
                        let m = parse_measurement(lex)?;
                        file.measurements.push(m);
                    }
                    "COMPU_METHOD" => {
                        let cm = parse_compu_method(lex)?;
                        file.compu_methods.insert(cm.name.clone(), cm);
                    }
                    "COMPU_VTAB" => {
                        let vt = parse_compu_vtab(lex)?;
                        file.compu_vtabs.insert(vt.name.clone(), vt);
                    }
                    "COMPU_VTAB_RANGE" => {
                        let vtr = parse_compu_vtab_range(lex)?;
                        file.compu_vtab_ranges.insert(vtr.name.clone(), vtr);
                    }
                    "CHARACTERISTIC" => {
                        let c = parse_characteristic(lex)?;
                        file.characteristics.push(c);
                    }
                    "AXIS_PTS" => {
                        let ap = parse_axis_pts_block(lex)?;
                        file.axis_pts.insert(ap.name.clone(), ap);
                    }
                    "RECORD_LAYOUT" => {
                        let rl = parse_record_layout(lex)?;
                        file.record_layouts.insert(rl.name.clone(), rl);
                    }
                    "FUNCTION" => {
                        let func = parse_function(lex)?;
                        file.functions.push(func);
                    }
                    _ => {
                        // Recurse into unknown blocks — they may contain nested items.
                        parse_block_contents(lex, file, Some(&kw))?;
                    }
                }
            }
            Some(_) => {} // bare tokens at this level — ignore
        }
    }
}

// ── MEASUREMENT ──────────────────────────────────────────────────────────────

fn parse_measurement(lex: &mut Lexer<'_>) -> Result<Measurement> {
    let name = expect_word(lex)?.to_string();
    let description = expect_string_or_word(lex)?.to_string();
    let datatype = parse_datatype(lex)?;
    let compu_method_ref = expect_word(lex)?.to_string();

    // resolution, accuracy, lower_limit, upper_limit  (skip them)
    expect_any(lex)?; // resolution
    expect_any(lex)?; // accuracy
    expect_any(lex)?; // lower_limit
    expect_any(lex)?; // upper_limit

    let mut ecu_address: Option<u32> = None;
    let mut bit_mask: Option<u64> = None;

    // Parse optional attributes until /end MEASUREMENT
    loop {
        match lex.next_token() {
            None => return Err(Error::UnexpectedEof),
            Some(tok) if tok.eq_word("/end") => {
                expect_keyword(lex, b"MEASUREMENT")?;
                break;
            }
            Some(tok) if tok.eq_word("/begin") => {
                // Sub-block (e.g. IF_DATA, ANNOTATION) — skip it.
                skip_block(lex, 1)?;
            }
            Some(tok) if tok.eq_word("ECU_ADDRESS") => {
                ecu_address = Some(parse_u32(lex)?);
            }
            Some(tok) if tok.eq_word("BIT_MASK") => {
                bit_mask = Some(parse_u64(lex)?);
            }
            Some(_) => {} // DISPLAY_IDENTIFIER, READ_WRITE, etc. — ignore
        }
    }

    Ok(Measurement {
        name,
        description,
        datatype,
        compu_method_ref,
        ecu_address,
        bit_mask,
    })
}

fn parse_datatype(lex: &mut Lexer<'_>) -> Result<DataType> {
    let tok = expect_word(lex)?;
    match tok.as_bytes() {
        b"UBYTE" => Ok(DataType::UByte),
        b"SBYTE" => Ok(DataType::SByte),
        b"UWORD" => Ok(DataType::UWord),
        b"SWORD" => Ok(DataType::SWord),
        b"ULONG" => Ok(DataType::ULong),
        b"SLONG" => Ok(DataType::SLong),
        b"A_UINT64" => Ok(DataType::AUint64),
        b"A_INT64" => Ok(DataType::AInt64),
        b"FLOAT32_IEEE" => Ok(DataType::Float32Ieee),
        b"FLOAT64_IEEE" => Ok(DataType::Float64Ieee),
        other => Err(Error::UnknownDatatype(
            String::from_utf8_lossy(other).into_owned(),
        )),
    }
}

// ── COMPU_METHOD ─────────────────────────────────────────────────────────────

fn parse_compu_method(lex: &mut Lexer<'_>) -> Result<CompuMethod> {
    let name = expect_word(lex)?.to_string();
    let description = expect_string_or_word(lex)?.to_string();
    let conv_type = expect_word(lex)?.to_string();
    let format = expect_string_or_word(lex)?.to_string();
    let unit = expect_string_or_word(lex)?.to_string();

    let mut conversion = match conv_type.as_str() {
        "IDENTICAL" => Conversion::Identical,
        "RAT_FUNC" => Conversion::RatFunc {
            a: 0.0,
            b: 1.0,
            c: 0.0,
            d: 0.0,
            e: 0.0,
            f: 1.0,
        },
        "LINEAR" => Conversion::Linear { a: 1.0, b: 0.0 },
        "TAB_VERB" | "VERB_SEQ" => Conversion::TabVerb {
            tab_ref: String::new(),
        },
        "FORM" => Conversion::Form {
            formula: String::new(),
        },
        other => Conversion::Other(other.to_string()),
    };

    // Parse optional sub-keywords until /end COMPU_METHOD
    loop {
        match lex.next_token() {
            None => return Err(Error::UnexpectedEof),
            Some(tok) if tok.eq_word("/end") => {
                expect_keyword(lex, b"COMPU_METHOD")?;
                break;
            }
            Some(tok) if tok.eq_word("/begin") => {
                skip_block(lex, 1)?;
            }
            Some(tok) if tok.eq_word("COEFFS") => {
                // COEFFS a b c d e f
                let a = parse_f64(lex)?;
                let b = parse_f64(lex)?;
                let c = parse_f64(lex)?;
                let d = parse_f64(lex)?;
                let e = parse_f64(lex)?;
                let f = parse_f64(lex)?;
                conversion = Conversion::RatFunc { a, b, c, d, e, f };
            }
            Some(tok) if tok.eq_word("COEFFS_LINEAR") => {
                let a = parse_f64(lex)?;
                let b = parse_f64(lex)?;
                conversion = Conversion::Linear { a, b };
            }
            Some(tok) if tok.eq_word("COMPU_TAB_REF") => {
                let tab_ref = expect_word(lex)?.to_string();
                conversion = Conversion::TabVerb { tab_ref };
            }
            Some(tok) if tok.eq_word("FORMULA") => {
                let formula = expect_string_or_word(lex)?.to_string();
                conversion = Conversion::Form { formula };
            }
            Some(_) => {} // STATUS_STRING_REF, etc.
        }
    }

    Ok(CompuMethod {
        name,
        description,
        format,
        unit,
        conversion,
    })
}

// ── COMPU_VTAB ────────────────────────────────────────────────────────────────

fn parse_compu_vtab(lex: &mut Lexer<'_>) -> Result<CompuVtab> {
    let name = expect_word(lex)?.to_string();
    let _description = expect_string_or_word(lex)?;
    let _tab_type = expect_word(lex)?; // TAB_VERB
    let count: usize = expect_word(lex)?.parse().unwrap_or(0);

    let mut entries = Vec::with_capacity(count);
    loop {
        match lex.next_token() {
            None => return Err(Error::UnexpectedEof),
            Some(tok) if tok.eq_word("/end") => {
                expect_keyword(lex, b"COMPU_VTAB")?;
                break;
            }
            Some(tok) if tok.eq_word("/begin") => {
                skip_block(lex, 1)?;
            }
            Some(tok) if tok.eq_word("DEFAULT_VALUE") => {
                // DEFAULT_VALUE "label" — skip
                expect_string_or_word(lex)?;
            }
            Some(key_tok) => {
                // key_tok is the numeric key; next token is the label string
                if let Ok(k) = parse_tok_i64(&key_tok) {
                    let label = expect_string_or_word(lex)?.to_string();
                    entries.push((k, label));
                }
                // else: unexpected token, skip
            }
        }
    }

    Ok(CompuVtab { name, entries })
}

// ── COMPU_VTAB_RANGE ──────────────────────────────────────────────────────────

fn parse_compu_vtab_range(lex: &mut Lexer<'_>) -> Result<CompuVtabRange> {
    let name = expect_word(lex)?.to_string();
    let _description = expect_string_or_word(lex)?;
    let count: usize = expect_word(lex)?.parse().unwrap_or(0);

    let mut entries = Vec::with_capacity(count);
    let mut default_label = None;

    loop {
        match lex.next_token() {
            None => return Err(Error::UnexpectedEof),
            Some(tok) if tok.eq_word("/end") => {
                expect_keyword(lex, b"COMPU_VTAB_RANGE")?;
                break;
            }
            Some(tok) if tok.eq_word("/begin") => {
                skip_block(lex, 1)?;
            }
            Some(tok) if tok.eq_word("DEFAULT_VALUE") => {
                default_label = Some(expect_string_or_word(lex)?.to_string());
            }
            Some(lo_tok) => {
                if let Ok(lo) = parse_tok_i64(&lo_tok) {
                    let hi = parse_i64(lex)?;
                    let label = expect_string_or_word(lex)?.to_string();
                    entries.push((lo, hi, label));
                }
            }
        }
    }

    Ok(CompuVtabRange {
        name,
        entries,
        default_label,
    })
}

// ── helpers ──────────────────────────────────────────────────────────────────

/// Skip one complete block including its `/end KEYWORD`.
/// `depth` = 1 means we are inside one `/begin`; we return after the matching `/end`.
fn skip_block(lex: &mut Lexer<'_>, mut depth: usize) -> Result<()> {
    while depth > 0 {
        match lex.next_token() {
            None => return Err(Error::UnexpectedEof),
            Some(tok) if tok.eq_word("/begin") => {
                expect_any(lex)?; // consume the block keyword
                depth += 1;
            }
            Some(tok) if tok.eq_word("/end") => {
                expect_any(lex)?; // consume the block keyword
                depth -= 1;
            }
            Some(_) => {}
        }
    }
    Ok(())
}

fn expect_any(lex: &mut Lexer<'_>) -> Result<String> {
    match lex.next_token() {
        Some(t) => Ok(t.as_str_lossy().into_owned()),
        None => Err(Error::UnexpectedEof),
    }
}

fn expect_word(lex: &mut Lexer<'_>) -> Result<String> {
    match lex.next_token() {
        Some(Token::Word(b)) => Ok(String::from_utf8_lossy(b).into_owned()),
        Some(Token::Str(_)) => Err(Error::ExpectedWord),
        None => Err(Error::UnexpectedEof),
    }
}

fn expect_string_or_word(lex: &mut Lexer<'_>) -> Result<String> {
    match lex.next_token() {
        Some(t) => Ok(t.as_str_lossy().into_owned()),
        None => Err(Error::UnexpectedEof),
    }
}

fn expect_keyword(lex: &mut Lexer<'_>, kw: &[u8]) -> Result<()> {
    match lex.next_token() {
        Some(Token::Word(b)) if b == kw => Ok(()),
        Some(Token::Word(b)) => Err(Error::UnexpectedKeyword {
            expected: String::from_utf8_lossy(kw).into_owned(),
            got: String::from_utf8_lossy(b).into_owned(),
        }),
        Some(_) => Err(Error::ExpectedWord),
        None => Err(Error::UnexpectedEof),
    }
}

fn parse_f64(lex: &mut Lexer<'_>) -> Result<f64> {
    let s = expect_word(lex)?;
    parse_f64_str(&s)
}

fn parse_f64_str(s: &str) -> Result<f64> {
    if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        let v = u64::from_str_radix(hex, 16).map_err(|_| Error::ParseFloat(s.to_string()))?;
        Ok(v as f64)
    } else {
        s.parse::<f64>()
            .map_err(|_| Error::ParseFloat(s.to_string()))
    }
}

fn parse_u32(lex: &mut Lexer<'_>) -> Result<u32> {
    let s = expect_word(lex)?;
    if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        u32::from_str_radix(hex, 16).map_err(|_| Error::ParseInt(s))
    } else {
        s.parse::<u32>().map_err(|_| Error::ParseInt(s))
    }
}

fn parse_u64(lex: &mut Lexer<'_>) -> Result<u64> {
    let s = expect_word(lex)?;
    if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        u64::from_str_radix(hex, 16).map_err(|_| Error::ParseInt(s))
    } else {
        s.parse::<u64>().map_err(|_| Error::ParseInt(s))
    }
}

fn parse_i64(lex: &mut Lexer<'_>) -> Result<i64> {
    let s = expect_word(lex)?;
    parse_tok_i64_str(&s)
}

fn parse_tok_i64(tok: &Token<'_>) -> Result<i64> {
    parse_tok_i64_str(&tok.as_str_lossy())
}

fn parse_tok_i64_str(s: &str) -> Result<i64> {
    if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        i64::from_str_radix(hex, 16)
            .or_else(|_| u64::from_str_radix(hex, 16).map(|v| v as i64))
            .map_err(|_| Error::ParseInt(s.to_string()))
    } else {
        s.parse::<i64>()
            .or_else(|_| s.parse::<f64>().map(|f| f as i64))
            .map_err(|_| Error::ParseInt(s.to_string()))
    }
}

fn parse_u16(lex: &mut Lexer<'_>) -> Result<u16> {
    let s = expect_word(lex)?;
    s.parse::<u16>()
        .or_else(|_| s.parse::<f64>().map(|f| f as u16))
        .map_err(|_| Error::ParseInt(s))
}

// ── CHARACTERISTIC ──────────────────────────────────────────────────────────

fn parse_characteristic(lex: &mut Lexer<'_>) -> Result<Characteristic> {
    let name = expect_word(lex)?;
    let description = expect_string_or_word(lex)?;
    let char_type = parse_characteristic_type(lex)?;
    let address = parse_u32(lex)?;
    let deposit = expect_word(lex)?;
    let max_diff = parse_f64(lex)?;
    let compu_method_ref = expect_word(lex)?;
    let lower_limit = parse_f64(lex)?;
    let upper_limit = parse_f64(lex)?;

    let mut axes = Vec::new();
    let mut format = None;
    let mut display_identifier = None;

    loop {
        match lex.next_token() {
            None => return Err(Error::UnexpectedEof),
            Some(tok) if tok.eq_word("/end") => {
                expect_keyword(lex, b"CHARACTERISTIC")?;
                break;
            }
            Some(tok) if tok.eq_word("/begin") => {
                let kw = expect_word(lex)?;
                match kw.as_str() {
                    "AXIS_DESCR" => axes.push(parse_axis_descr(lex)?),
                    _ => {
                        skip_block(lex, 1)?;
                    }
                }
            }
            Some(tok) if tok.eq_word("FORMAT") => {
                format = Some(expect_string_or_word(lex)?);
            }
            Some(tok) if tok.eq_word("DISPLAY_IDENTIFIER") => {
                display_identifier = Some(expect_word(lex)?);
            }
            Some(_) => {} // READ_ONLY, EXTENDED_LIMITS, etc.
        }
    }

    Ok(Characteristic {
        name,
        description,
        char_type,
        address,
        deposit,
        max_diff,
        compu_method_ref,
        lower_limit,
        upper_limit,
        axes,
        format,
        display_identifier,
    })
}

fn parse_characteristic_type(lex: &mut Lexer<'_>) -> Result<CharacteristicType> {
    let tok = expect_word(lex)?;
    match tok.as_str() {
        "VALUE" => Ok(CharacteristicType::Value),
        "CURVE" => Ok(CharacteristicType::Curve),
        "MAP" => Ok(CharacteristicType::Map),
        "CUBOID" => Ok(CharacteristicType::Cuboid),
        "CUBE_4" => Ok(CharacteristicType::Cube4),
        "CUBE_5" => Ok(CharacteristicType::Cube5),
        "VAL_BLK" => Ok(CharacteristicType::ValBlk),
        "ASCII" => Ok(CharacteristicType::Ascii),
        other => Err(Error::UnknownDatatype(other.to_string())),
    }
}

// ── AXIS_DESCR ──────────────────────────────────────────────────────────────

fn parse_axis_descr(lex: &mut Lexer<'_>) -> Result<AxisDescr> {
    let attribute = parse_axis_attribute(lex)?;
    let input_quantity = expect_word(lex)?;
    let compu_method_ref = expect_word(lex)?;
    let max_axis_points = parse_u16(lex)?;
    let lower_limit = parse_f64(lex)?;
    let upper_limit = parse_f64(lex)?;

    let mut axis_pts_ref = None;
    let mut fix_axis_par_dist = None;
    let mut fix_axis_par_list = None;
    let mut format = None;

    loop {
        match lex.next_token() {
            None => return Err(Error::UnexpectedEof),
            Some(tok) if tok.eq_word("/end") => {
                expect_keyword(lex, b"AXIS_DESCR")?;
                break;
            }
            Some(tok) if tok.eq_word("/begin") => {
                let kw = expect_word(lex)?;
                match kw.as_str() {
                    "FIX_AXIS_PAR_LIST" => {
                        let mut vals = Vec::new();
                        loop {
                            match lex.next_token() {
                                None => return Err(Error::UnexpectedEof),
                                Some(t) if t.eq_word("/end") => {
                                    expect_keyword(lex, b"FIX_AXIS_PAR_LIST")?;
                                    break;
                                }
                                Some(t) => {
                                    if let Ok(v) = parse_f64_str(&t.as_str_lossy()) {
                                        vals.push(v);
                                    }
                                }
                            }
                        }
                        fix_axis_par_list = Some(vals);
                    }
                    _ => {
                        skip_block(lex, 1)?;
                    }
                }
            }
            Some(tok) if tok.eq_word("AXIS_PTS_REF") => {
                axis_pts_ref = Some(expect_word(lex)?);
            }
            Some(tok) if tok.eq_word("FIX_AXIS_PAR_DIST") => {
                let offset = parse_f64(lex)?;
                let distance = parse_f64(lex)?;
                let count = parse_u16(lex)?;
                fix_axis_par_dist = Some(FixAxisParDist {
                    offset,
                    distance,
                    count,
                });
            }
            Some(tok) if tok.eq_word("FORMAT") => {
                format = Some(expect_string_or_word(lex)?);
            }
            Some(_) => {} // READ_ONLY, DEPOSIT, etc.
        }
    }

    Ok(AxisDescr {
        attribute,
        input_quantity,
        compu_method_ref,
        max_axis_points,
        lower_limit,
        upper_limit,
        axis_pts_ref,
        fix_axis_par_dist,
        fix_axis_par_list,
        format,
    })
}

fn parse_axis_attribute(lex: &mut Lexer<'_>) -> Result<AxisAttribute> {
    let tok = expect_word(lex)?;
    match tok.as_str() {
        "STD_AXIS" => Ok(AxisAttribute::StdAxis),
        "COM_AXIS" => Ok(AxisAttribute::ComAxis),
        "FIX_AXIS" => Ok(AxisAttribute::FixAxis),
        "CURVE_AXIS" => Ok(AxisAttribute::CurveAxis),
        "RES_AXIS" => Ok(AxisAttribute::ResAxis),
        other => Err(Error::UnknownDatatype(other.to_string())),
    }
}

// ── AXIS_PTS ────────────────────────────────────────────────────────────────

fn parse_axis_pts_block(lex: &mut Lexer<'_>) -> Result<AxisPts> {
    let name = expect_word(lex)?;
    let description = expect_string_or_word(lex)?;
    let address = parse_u32(lex)?;
    let input_quantity = expect_word(lex)?;
    let deposit = expect_word(lex)?;
    let max_diff = parse_f64(lex)?;
    let compu_method_ref = expect_word(lex)?;
    let max_axis_points = parse_u16(lex)?;
    let lower_limit = parse_f64(lex)?;
    let upper_limit = parse_f64(lex)?;

    let mut format = None;

    loop {
        match lex.next_token() {
            None => return Err(Error::UnexpectedEof),
            Some(tok) if tok.eq_word("/end") => {
                expect_keyword(lex, b"AXIS_PTS")?;
                break;
            }
            Some(tok) if tok.eq_word("/begin") => {
                skip_block(lex, 1)?;
            }
            Some(tok) if tok.eq_word("FORMAT") => {
                format = Some(expect_string_or_word(lex)?);
            }
            Some(_) => {}
        }
    }

    Ok(AxisPts {
        name,
        description,
        address,
        input_quantity,
        deposit,
        max_diff,
        compu_method_ref,
        max_axis_points,
        lower_limit,
        upper_limit,
        format,
    })
}

// ── RECORD_LAYOUT ───────────────────────────────────────────────────────────

fn parse_record_layout(lex: &mut Lexer<'_>) -> Result<RecordLayout> {
    let name = expect_word(lex)?;

    let mut layout = RecordLayout {
        name,
        ..Default::default()
    };

    loop {
        match lex.next_token() {
            None => return Err(Error::UnexpectedEof),
            Some(tok) if tok.eq_word("/end") => {
                expect_keyword(lex, b"RECORD_LAYOUT")?;
                break;
            }
            Some(tok) if tok.eq_word("/begin") => {
                skip_block(lex, 1)?;
            }
            Some(tok) if tok.eq_word("FNC_VALUES") => {
                let position = parse_u16(lex)?;
                let datatype = parse_datatype(lex)?;
                let index_mode = expect_word(lex)?;
                let _addressing = expect_word(lex)?; // DIRECT
                layout.fnc_values = Some(FncValuesField {
                    position,
                    datatype,
                    column_dir: index_mode != "ROW_DIR",
                });
            }
            Some(tok) if tok.eq_word("NO_AXIS_PTS_X") => {
                let position = parse_u16(lex)?;
                let datatype = parse_datatype(lex)?;
                layout.no_axis_pts_x = Some(LayoutField { position, datatype });
            }
            Some(tok) if tok.eq_word("AXIS_PTS_X") => {
                let position = parse_u16(lex)?;
                let datatype = parse_datatype(lex)?;
                let _index_mode = expect_word(lex)?; // INDEX_INCR
                let _addressing = expect_word(lex)?; // DIRECT
                layout.axis_pts_x = Some(LayoutField { position, datatype });
            }
            Some(tok) if tok.eq_word("NO_AXIS_PTS_Y") => {
                let position = parse_u16(lex)?;
                let datatype = parse_datatype(lex)?;
                layout.no_axis_pts_y = Some(LayoutField { position, datatype });
            }
            Some(tok) if tok.eq_word("AXIS_PTS_Y") => {
                let position = parse_u16(lex)?;
                let datatype = parse_datatype(lex)?;
                let _index_mode = expect_word(lex)?;
                let _addressing = expect_word(lex)?;
                layout.axis_pts_y = Some(LayoutField { position, datatype });
            }
            Some(tok) if tok.eq_word("FIX_NO_AXIS_PTS_X") => {
                layout.fix_no_axis_pts_x = Some(parse_u16(lex)?);
            }
            Some(tok) if tok.eq_word("FIX_NO_AXIS_PTS_Y") => {
                layout.fix_no_axis_pts_y = Some(parse_u16(lex)?);
            }
            Some(tok) if tok.eq_word("AXIS_PTS_Z") => {
                let position = parse_u16(lex)?;
                let datatype = parse_datatype(lex)?;
                let _index_mode = expect_word(lex)?;
                let _addressing = expect_word(lex)?;
                layout.axis_pts_z = Some(LayoutField { position, datatype });
            }
            Some(tok) if tok.eq_word("NO_AXIS_PTS_Z") => {
                let position = parse_u16(lex)?;
                let datatype = parse_datatype(lex)?;
                layout.no_axis_pts_z = Some(LayoutField { position, datatype });
            }
            Some(tok) if tok.eq_word("FIX_NO_AXIS_PTS_Z") => {
                layout.fix_no_axis_pts_z = Some(parse_u16(lex)?);
            }
            Some(_) => {} // ALIGNMENT_*, RESERVED, SRC_ADDR_*, etc.
        }
    }

    Ok(layout)
}

// ── FUNCTION ────────────────────────────────────────────────────────────

fn parse_function(lex: &mut Lexer<'_>) -> Result<Function> {
    let name = expect_word(lex)?;
    let description = expect_string_or_word(lex)?;

    let mut def_characteristics = Vec::new();
    let mut ref_characteristics = Vec::new();
    let mut sub_functions = Vec::new();

    loop {
        match lex.next_token() {
            None => return Err(Error::UnexpectedEof),
            Some(tok) if tok.eq_word("/end") => {
                expect_keyword(lex, b"FUNCTION")?;
                break;
            }
            Some(tok) if tok.eq_word("/begin") => {
                let kw = expect_word(lex)?;
                match kw.as_str() {
                    "DEF_CHARACTERISTIC" => {
                        parse_name_list(lex, &mut def_characteristics, "DEF_CHARACTERISTIC")?;
                    }
                    "REF_CHARACTERISTIC" => {
                        parse_name_list(lex, &mut ref_characteristics, "REF_CHARACTERISTIC")?;
                    }
                    "SUB_FUNCTION" => {
                        parse_name_list(lex, &mut sub_functions, "SUB_FUNCTION")?;
                    }
                    _ => {
                        skip_block(lex, 1)?;
                    }
                }
            }
            Some(_) => {} // FUNCTION_VERSION, etc.
        }
    }

    Ok(Function {
        name,
        description,
        def_characteristics,
        ref_characteristics,
        sub_functions,
    })
}

/// Parse a list of names terminated by `/end KEYWORD`.
fn parse_name_list(lex: &mut Lexer<'_>, out: &mut Vec<String>, end_kw: &str) -> Result<()> {
    loop {
        match lex.next_token() {
            None => return Err(Error::UnexpectedEof),
            Some(tok) if tok.eq_word("/end") => {
                let kw = expect_word(lex)?;
                if kw != end_kw {
                    return Err(Error::UnexpectedKeyword {
                        expected: end_kw.to_string(),
                        got: kw,
                    });
                }
                return Ok(());
            }
            Some(tok) if tok.eq_word("/begin") => {
                // Shouldn't happen inside name lists, but be safe
                skip_block(lex, 1)?;
            }
            Some(tok) => {
                out.push(tok.as_str_lossy().into_owned());
            }
        }
    }
}
