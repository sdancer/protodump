fn sanitise_ident(raw: &str) -> String {
    let mut s = raw
        .to_lowercase()
        .replace(|c: char| !c.is_ascii_alphanumeric(), "_");
    if s.is_empty() {
        s.push_str("field");
    }
    if s.starts_with(|c: char| c.is_ascii_digit()) {
        s.insert(0, '_');
    }
    // Handle Rust keywords quickly
    if [
        "type", "match", "struct", "enum", "fn", "crate", "self", "super", "mod",
    ]
    .contains(&s.as_str())
    {
        s.push('_');
    }
    s
}

fn sanitise_struct(raw: &str) -> String {
    let mut s = raw.to_string();
    if !s
        .chars()
        .next()
        .map(|arg0: char| char::is_ascii_uppercase(&arg0))
        .unwrap_or(false)
    {
        s = format!(
            "{}{}",
            s.chars().next().unwrap().to_ascii_uppercase(),
            &s[1..]
        );
    }
    s.replace(|c: char| !c.is_ascii_alphanumeric(), "")
}

fn rust_ty_from_kind(kind: &FieldType, fld: &Field) -> String {
    use FieldType::*;
    match kind {
        U8 => "u8".into(),
        I32 => "i32".into(),
        I64 => "i64".into(),
        F32 => "f32".into(),
        StringUtf16 => "String".into(),
        Array => {
            // element_type carries (FieldType, ty_ptr).  Recurse if present.
            //if let Some((elem_kind, _elem_ptr)) = &fld.element_type {
            //    format!("Vec<{}>", rust_ty_from_kind(elem_kind, fld))
            //} else {
            //    "Vec<u8>".into()
            //}
            "array".into()
        }
        Struct => {
            // resolve by ty_ptr → ClassInfo, else placeholder
            //CLASSES_BY_ADDR
            //    .get(&fld.ty_ptr)
            //    .map(|cls| sanitise_struct(&cls.name))
            //    .unwrap_or_else(|| "() /*Struct*/".into())
            "not_supported".into()
        }
        Enum => {
            //ENUMS_BY_ADDR
            //    .get(&fld.ty_ptr)
            //    .map(|e| sanitise_struct(&e.name))
            //    .unwrap_or("u32 /*Enum*/".into())
            "enum".into()
        }
        Bool => "bool".into(),
        Unknown(_) => "[u8;0] /*Unknown*/".into(),
    }
}

fn generate_rust(packets: &[PacketInfo]) -> String {
    let mut out = String::from("// Auto-generated – DO NOT EDIT\n\n");

    for pkt in packets {
        let struct_name = sanitise_struct(&pkt.name);
        out += &format!("pub struct {} {{\n", struct_name);

        for fld in &pkt.fields {
            let rust_ty = rust_ty_from_kind(&fld.f_type, fld);
            out += &format!(
                "    pub {}: {}, // {:?}\n",
                sanitise_ident(&fld.name),
                rust_ty,
                fld.f_type // keeps original enum for debugging
            );
        }
        out += "}\n\n";
    }
    out
}
