use arrow::array::{Array, ArrayRef, RecordBatch, RecordBatchReader, StringArray, StringBuilder};
use arrow::datatypes::{DataType, Field, FieldRef, Schema, SchemaRef};
use arrow::json::writer::{EncoderOptions, LineDelimited, make_encoder};
use parquet::arrow::ArrowWriter;
use parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder;
use parquet::basic::Compression;
use parquet::file::properties::WriterProperties;
use serde_json::Value as JsonValue;
use std::collections::BTreeSet;
use std::io::Cursor;
use std::sync::Arc;

type Table = (SchemaRef, Vec<RecordBatch>);
type ColumnData = Vec<Vec<Option<String>>>;

/// Normalized representation returned by tabular conversions so the JS side can
/// build downloads with accurate MIME and filenames.
#[derive(Debug, Clone, PartialEq)]
pub struct TabularResult {
    pub bytes: Vec<u8>,
    pub mime_type: String,
    pub file_name: String,
    pub row_count: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TabularFormat {
    Json,
    Csv,
    Tsv,
    Parquet,
    Avro,
    ArrowIpc,
    Feather,
}

impl TabularFormat {
    fn parse(name: &str) -> Option<Self> {
        match name.trim().to_lowercase().as_str() {
            "json" => Some(Self::Json),
            "csv" => Some(Self::Csv),
            "tsv" => Some(Self::Tsv),
            "parquet" => Some(Self::Parquet),
            "avro" => Some(Self::Avro),
            "arrow ipc" | "arrow" | "ipc" => Some(Self::ArrowIpc),
            "arrow feather" | "feather" => Some(Self::Feather),
            _ => None,
        }
    }

    fn mime_and_ext(&self) -> (&'static str, &'static str) {
        match self {
            Self::Json => ("application/json", "json"),
            Self::Csv => ("text/csv", "csv"),
            Self::Tsv => ("text/tab-separated-values", "tsv"),
            Self::Parquet => ("application/x-parquet", "parquet"),
            Self::Avro => ("application/avro", "avro"),
            Self::ArrowIpc | Self::Feather => ("application/vnd.apache.arrow.file", "arrow"),
        }
    }

    fn delimiter(&self) -> Option<u8> {
        match self {
            Self::Csv => Some(b','),
            Self::Tsv => Some(b'\t'),
            _ => None,
        }
    }
}

fn err<T: std::fmt::Display>(msg: T) -> String {
    msg.to_string()
}

/// Parse tabular data into a schema plus batches. Text formats become `Utf8`
/// columns: guessing types from text would turn a zip code like `00123` into
/// `123`. Binary formats keep the schema their producer wrote.
fn read_table(fmt: TabularFormat, data: &[u8]) -> Result<Table, String> {
    match fmt {
        TabularFormat::Json => parse_json_rows(data),
        TabularFormat::Csv | TabularFormat::Tsv => parse_delimited_rows(fmt, data),
        TabularFormat::Parquet => {
            let reader =
                ParquetRecordBatchReaderBuilder::try_new(bytes::Bytes::copy_from_slice(data))
                    .map_err(err)?
                    .build()
                    .map_err(err)?;
            collect_batches(reader)
        }
        TabularFormat::Avro => {
            let reader = arrow_avro::reader::ReaderBuilder::new()
                .build(Cursor::new(data))
                .map_err(err)?;
            collect_batches(reader)
        }
        TabularFormat::ArrowIpc | TabularFormat::Feather => {
            let reader =
                arrow::ipc::reader::FileReader::try_new(Cursor::new(data), None).map_err(err)?;
            collect_batches(reader)
        }
    }
}

fn collect_batches(reader: impl RecordBatchReader) -> Result<Table, String> {
    let schema = reader.schema();
    let batches = reader.collect::<Result<Vec<_>, _>>().map_err(err)?;
    Ok((schema, batches))
}

fn parse_json_rows(data: &[u8]) -> Result<Table, String> {
    let text = std::str::from_utf8(data).map_err(err)?;
    let parsed: JsonValue = if text.trim_start().starts_with('[') {
        serde_json::from_str(text).map_err(err)?
    } else {
        let mut rows = Vec::new();
        for line in text.lines() {
            if line.trim().is_empty() {
                continue;
            }
            let value: JsonValue = serde_json::from_str(line).map_err(err)?;
            rows.push(value);
        }
        JsonValue::Array(rows)
    };
    let rows = match parsed {
        JsonValue::Array(items) => items,
        other => return Err(format!("Expected JSON array or NDJSON, got {other}")),
    };
    json_values_to_table(rows)
}

fn json_values_to_table(rows: Vec<JsonValue>) -> Result<Table, String> {
    let mut key_set = BTreeSet::new();
    for value in &rows {
        let obj = value
            .as_object()
            .ok_or_else(|| "JSON rows must be objects".to_string())?;
        for key in obj.keys() {
            key_set.insert(key.clone());
        }
    }
    let names: Vec<String> = key_set.into_iter().collect();
    let mut columns: Vec<Vec<Option<String>>> = names.iter().map(|_| Vec::new()).collect();
    for value in rows {
        let obj = value
            .as_object()
            .ok_or_else(|| "JSON rows must be objects".to_string())?;
        for (col_idx, name) in names.iter().enumerate() {
            let cell = obj
                .get(name)
                .map(json_cell_to_string)
                .transpose()?
                .flatten();
            columns[col_idx].push(cell);
        }
    }
    text_table(names, columns)
}

fn json_cell_to_string(value: &JsonValue) -> Result<Option<String>, String> {
    match value {
        JsonValue::Null => Ok(None),
        JsonValue::Bool(b) => Ok(Some(b.to_string())),
        JsonValue::Number(num) => Ok(Some(num.to_string())),
        JsonValue::String(s) => Ok(Some(s.clone())),
        other => serde_json::to_string(other)
            .map(Some)
            .map_err(|e| format!("Failed to encode nested value: {e}")),
    }
}

fn parse_delimited_rows(fmt: TabularFormat, data: &[u8]) -> Result<Table, String> {
    let mut reader = csv::ReaderBuilder::new()
        .has_headers(true)
        .delimiter(fmt.delimiter().unwrap_or(b','))
        .from_reader(Cursor::new(data));

    let headers = reader.headers().map_err(err)?.clone();
    let mut columns: Vec<Vec<Option<String>>> = vec![Vec::new(); headers.len()];
    for record in reader.records() {
        let rec = record.map_err(err)?;
        for (idx, field) in rec.iter().enumerate() {
            columns[idx].push(if field.is_empty() {
                None
            } else {
                Some(field.to_string())
            });
        }
    }
    text_table(headers.iter().map(|s| s.to_string()).collect(), columns)
}

fn text_table(names: Vec<String>, columns: ColumnData) -> Result<Table, String> {
    let schema = Arc::new(Schema::new(
        names
            .iter()
            .map(|name| Field::new(name, DataType::Utf8, true))
            .collect::<Vec<_>>(),
    ));
    if names.is_empty() {
        return Ok((schema, Vec::new()));
    }
    let arrays: Vec<ArrayRef> = columns
        .into_iter()
        .map(|col| Arc::new(StringArray::from(col)) as ArrayRef)
        .collect();
    let batch = RecordBatch::try_new(schema.clone(), arrays).map_err(err)?;
    Ok((schema, vec![batch]))
}

fn write_table(fmt: TabularFormat, (schema, batches): &Table) -> Result<Vec<u8>, String> {
    match fmt {
        TabularFormat::Json => write_json(batches),
        TabularFormat::Csv | TabularFormat::Tsv => {
            write_delimited(fmt.delimiter().unwrap_or(b','), schema, batches)
        }
        TabularFormat::Parquet => {
            // Snappy is what pyarrow, pandas and Spark write by default, so every
            // reader that matters has it.
            let props = WriterProperties::builder()
                .set_compression(Compression::SNAPPY)
                .build();
            let mut writer =
                ArrowWriter::try_new(Vec::new(), schema.clone(), Some(props)).map_err(err)?;
            for batch in batches {
                writer.write(batch).map_err(err)?;
            }
            writer.into_inner().map_err(err)
        }
        TabularFormat::Avro => {
            let schema = avro_named(schema);
            let mut writer =
                arrow_avro::writer::AvroWriter::new(Vec::new(), schema.as_ref().clone())
                    .map_err(err)?;
            for batch in batches {
                let batch =
                    RecordBatch::try_new(schema.clone(), batch.columns().to_vec()).map_err(err)?;
                writer.write(&batch).map_err(err)?;
            }
            writer.finish().map_err(err)?;
            Ok(writer.into_inner())
        }
        TabularFormat::ArrowIpc | TabularFormat::Feather => {
            let mut writer =
                arrow::ipc::writer::FileWriter::try_new(Vec::new(), schema).map_err(err)?;
            for batch in batches {
                writer.write(batch).map_err(err)?;
            }
            writer.finish().map_err(err)?;
            writer.into_inner().map_err(err)
        }
    }
}

/// Avro names are `[A-Za-z_][A-Za-z0-9_]*`, and CSV headers like `first name` are
/// not. arrow-avro rewrites them in the schema it writes but then looks columns up
/// by the rewritten name and fails, so rename before it sees them.
fn avro_named(schema: &SchemaRef) -> SchemaRef {
    let mut taken = BTreeSet::new();
    let fields: Vec<Field> = schema
        .fields()
        .iter()
        .map(|field| {
            let mut name: String = field
                .name()
                .chars()
                .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
                .collect();
            if !name.starts_with(|c: char| c.is_ascii_alphabetic() || c == '_') {
                name.insert(0, '_');
            }
            let base = name.clone();
            let mut n = 1;
            while !taken.insert(name.clone()) {
                n += 1;
                name = format!("{base}_{n}");
            }
            field.as_ref().clone().with_name(name)
        })
        .collect();
    Arc::new(Schema::new(fields))
}

/// A JSON array with one object per line. Pretty-printing would mean re-parsing,
/// which rounds decimals and drops their trailing zeros.
fn write_json(batches: &[RecordBatch]) -> Result<Vec<u8>, String> {
    let mut writer = arrow::json::WriterBuilder::new()
        .with_explicit_nulls(true)
        .build::<_, LineDelimited>(Vec::new());
    for batch in batches {
        writer.write(batch).map_err(err)?;
    }
    writer.finish().map_err(err)?;
    let lines = writer.into_inner();
    let rows: Vec<&[u8]> = lines
        .split(|b| *b == b'\n')
        .filter(|line| !line.is_empty())
        .collect();
    if rows.is_empty() {
        return Ok(b"[]".to_vec());
    }
    let mut out = b"[\n".to_vec();
    out.extend(rows.join(&b",\n"[..]));
    out.extend(b"\n]\n");
    Ok(out)
}

fn write_delimited(
    delimiter: u8,
    schema: &SchemaRef,
    batches: &[RecordBatch],
) -> Result<Vec<u8>, String> {
    let empty = [RecordBatch::new_empty(schema.clone())];
    // The header is written with the first batch, so a table without rows still
    // needs one to keep its column names.
    let batches = if batches.is_empty() {
        &empty[..]
    } else {
        batches
    };
    let mut writer = arrow::csv::WriterBuilder::new()
        .with_header(true)
        .with_delimiter(delimiter)
        .build(Vec::new());
    for batch in batches {
        writer.write(&nested_as_json(batch)?).map_err(err)?;
    }
    Ok(writer.into_inner())
}

/// CSV has no lists or structs; spell those cells as JSON, the same text a JSON
/// input's nested values get when they become CSV.
fn nested_as_json(batch: &RecordBatch) -> Result<RecordBatch, String> {
    let schema = batch.schema();
    if !schema.fields().iter().any(|f| f.data_type().is_nested()) {
        return Ok(batch.clone());
    }
    let mut fields = Vec::with_capacity(schema.fields().len());
    let mut columns = Vec::with_capacity(schema.fields().len());
    for (field, column) in schema.fields().iter().zip(batch.columns()) {
        if field.data_type().is_nested() {
            fields.push(Field::new(field.name(), DataType::Utf8, true));
            columns.push(json_cells(field, column.as_ref())?);
        } else {
            fields.push(field.as_ref().clone());
            columns.push(column.clone());
        }
    }
    RecordBatch::try_new(Arc::new(Schema::new(fields)), columns).map_err(err)
}

fn json_cells(field: &FieldRef, array: &dyn Array) -> Result<ArrayRef, String> {
    let options = EncoderOptions::default();
    let mut encoder = make_encoder(field, array, &options).map_err(err)?;
    let mut cells = StringBuilder::new();
    let mut buf = Vec::new();
    for idx in 0..array.len() {
        if encoder.is_null(idx) {
            cells.append_null();
            continue;
        }
        buf.clear();
        encoder.encode(idx, &mut buf);
        cells.append_value(std::str::from_utf8(&buf).map_err(err)?);
    }
    Ok(Arc::new(cells.finish()))
}

/// Main entry point used by wasm_bindgen wrapper.
pub fn convert_tabular(from: &str, to: &str, data: &[u8]) -> Result<TabularResult, String> {
    let from_fmt =
        TabularFormat::parse(from).ok_or_else(|| format!("Unsupported source format: {from}"))?;
    let to_fmt =
        TabularFormat::parse(to).ok_or_else(|| format!("Unsupported target format: {to}"))?;
    let table = read_table(from_fmt, data)?;
    let row_count = table.1.iter().map(|b| b.num_rows() as u64).sum();
    let bytes = write_table(to_fmt, &table)?;
    let (mime, ext) = to_fmt.mime_and_ext();
    Ok(TabularResult {
        bytes,
        mime_type: mime.to_string(),
        file_name: format!("converted.{ext}"),
        row_count,
    })
}

/// Heuristic helper that guesses a tabular format from a file extension. Used by the
/// front-end to pre-select dropdowns but kept here for reuse in tests.
#[allow(dead_code)]
pub fn infer_format_from_name(name: &str) -> Option<TabularFormat> {
    let lowered = name.to_lowercase();
    if lowered.ends_with(".parquet") {
        Some(TabularFormat::Parquet)
    } else if lowered.ends_with(".avro") {
        Some(TabularFormat::Avro)
    } else if lowered.ends_with(".arrow")
        || lowered.ends_with(".ipc")
        || lowered.ends_with(".feather")
    {
        Some(TabularFormat::ArrowIpc)
    } else if lowered.ends_with(".tsv") {
        Some(TabularFormat::Tsv)
    } else if lowered.ends_with(".csv") {
        Some(TabularFormat::Csv)
    } else if lowered.ends_with(".json") || lowered.ends_with(".ndjson") {
        Some(TabularFormat::Json)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn sample_rows() -> Vec<u8> {
        json!([
            {"id": 1, "name": "Ada"},
            {"id": 2, "name": "Bob"}
        ])
        .to_string()
        .into_bytes()
    }

    #[test]
    fn json_to_parquet_and_back() {
        let parquet = convert_tabular("JSON", "Parquet", &sample_rows()).expect("json -> parquet");
        assert_eq!(parquet.mime_type, "application/x-parquet");
        let back = convert_tabular("Parquet", "JSON", &parquet.bytes).expect("parquet -> json");
        let text = String::from_utf8(back.bytes).unwrap();
        assert!(text.contains("Ada"));
        assert_eq!(back.row_count, 2);
    }

    #[test]
    fn csv_to_ipc_round_trip() {
        let csv = b"id,name\n1,Ada\n2,Bob\n";
        let ipc = convert_tabular("CSV", "Arrow IPC", csv).expect("csv -> ipc");
        assert!(ipc.bytes.len() > 12);
        let back = convert_tabular("Arrow IPC", "CSV", &ipc.bytes).expect("ipc -> csv");
        let text = String::from_utf8(back.bytes).unwrap();
        assert!(text.contains("Ada"));
        assert!(text.contains("Bob"));
    }

    #[test]
    fn json_to_avro_round_trip() {
        let avro = convert_tabular("JSON", "Avro", &sample_rows()).expect("json -> avro");
        assert_eq!(avro.mime_type, "application/avro");
        assert!(avro.bytes.len() > 20);
        let back = convert_tabular("Avro", "JSON", &avro.bytes).expect("avro -> json");
        let text = String::from_utf8(back.bytes).unwrap();
        assert!(text.contains("Ada"));
    }

    /// A typed table as a parquet/arrow producer hands it over: the columns the old
    /// converter printed as type names, plus a nested one.
    fn typed_ipc() -> Vec<u8> {
        use arrow::array::{
            Date32Array, Decimal128Array, Int8Array, ListBuilder, TimestampMillisecondArray,
        };
        let mut tags = ListBuilder::new(StringBuilder::new());
        tags.values().append_value("a");
        tags.values().append_value("b");
        tags.append(true);
        tags.append_null();
        let columns: Vec<ArrayRef> = vec![
            Arc::new(Int8Array::from(vec![Some(7), None])),
            // 2026-10-28T12:00:00
            Arc::new(TimestampMillisecondArray::from(vec![
                Some(1_793_188_800_000),
                None,
            ])),
            // 2026-01-01
            Arc::new(Date32Array::from(vec![Some(20_454), None])),
            Arc::new(
                Decimal128Array::from(vec![Some(999), None])
                    .with_precision_and_scale(10, 2)
                    .unwrap(),
            ),
            Arc::new(tags.finish()),
        ];
        let fields: Vec<Field> = ["small", "ts", "day", "price", "tags"]
            .iter()
            .zip(&columns)
            .map(|(name, col)| Field::new(*name, col.data_type().clone(), true))
            .collect();
        let schema = Arc::new(Schema::new(fields));
        let batch = RecordBatch::try_new(schema.clone(), columns).unwrap();
        let mut writer = arrow::ipc::writer::FileWriter::try_new(Vec::new(), &schema).unwrap();
        writer.write(&batch).unwrap();
        writer.finish().unwrap();
        writer.into_inner().unwrap()
    }

    #[test]
    fn typed_columns_survive_every_binary_target() {
        let ipc = typed_ipc();
        for target in ["Parquet", "Avro", "Arrow IPC"] {
            let out = convert_tabular("Arrow IPC", target, &ipc).expect(target);
            let back = convert_tabular(target, "JSON", &out.bytes).expect(target);
            let text = String::from_utf8(back.bytes).unwrap();
            for want in [
                "\"small\":7",
                "2026-10-28T12:00:00",
                "\"day\":\"2026-01-01\"",
                "9.99",
                "[\"a\",\"b\"]",
            ] {
                assert!(text.contains(want), "{target}: {want} missing in {text}");
            }
            assert_eq!(back.row_count, 2, "{target}");
        }
    }

    #[test]
    fn nested_cells_export_to_csv_as_json() {
        let out = convert_tabular("Arrow IPC", "CSV", &typed_ipc()).expect("ipc -> csv");
        let mut reader = csv::Reader::from_reader(out.bytes.as_slice());
        let headers = reader.headers().unwrap().clone();
        assert_eq!(headers.get(4), Some("tags"));
        let rows: Vec<csv::StringRecord> = reader.records().map(Result::unwrap).collect();
        assert_eq!(&rows[0][4], r#"["a","b"]"#);
        assert_eq!(&rows[1][4], "");
    }

    #[test]
    fn text_inputs_keep_leading_zeros() {
        let parquet = convert_tabular("CSV", "Parquet", b"zip\n00123\n").expect("csv -> parquet");
        let back = convert_tabular("Parquet", "JSON", &parquet.bytes).expect("parquet -> json");
        let text = String::from_utf8(back.bytes).unwrap();
        assert!(text.contains("\"zip\":\"00123\""), "{text}");
    }

    /// Avro readers reject names with spaces or a leading digit, so CSV headers are
    /// rewritten; colliding rewrites must not merge two columns into one.
    #[test]
    fn csv_headers_become_avro_names() {
        let csv = b"first name,2024,first_name\nAda,x,y\n";
        let avro = convert_tabular("CSV", "Avro", csv).expect("csv -> avro");
        let back = convert_tabular("Avro", "CSV", &avro.bytes).expect("avro -> csv");
        assert_eq!(
            String::from_utf8(back.bytes).unwrap(),
            "first_name,_2024,first_name_2\nAda,x,y\n"
        );
    }

    #[test]
    fn header_only_table_keeps_its_columns() {
        let parquet = convert_tabular("CSV", "Parquet", b"a,b\n").expect("csv -> parquet");
        assert_eq!(parquet.row_count, 0);
        let back = convert_tabular("Parquet", "CSV", &parquet.bytes).expect("parquet -> csv");
        assert_eq!(String::from_utf8(back.bytes).unwrap(), "a,b\n");
    }

    /// Files from the outside world, not from this converter: a round trip through
    /// our own writer can't catch a codec we never enabled or a type we can only
    /// write as text. Fixtures come from docs/scripts/tabular-interop.sh.
    #[test]
    #[ignore = "needs TABULAR_FIXTURES from docs/scripts/tabular-interop.sh"]
    fn reads_files_written_by_pyarrow_and_fastavro() {
        let dir = std::env::var("TABULAR_FIXTURES").expect("TABULAR_FIXTURES");
        // (file, format, rows, values that must appear in the JSON output)
        let typed = &["2026-10-28", "2026-01-01", "9.99", "alice"][..];
        let cases = [
            ("snappy.parquet", "Parquet", 3, typed),
            ("zstd.parquet", "Parquet", 3, typed),
            ("plain.parquet", "Parquet", 3, typed),
            ("lz4.feather", "Feather", 3, typed),
            ("plain.arrow", "Arrow IPC", 3, typed),
            ("null.avro", "Avro", 2, &["2026-10-28", "alice"][..]),
            ("deflate.avro", "Avro", 2, &["2026-10-28", "alice"][..]),
            ("snappy.avro", "Avro", 2, &["2026-10-28", "alice"][..]),
        ];
        // What the old fallback printed instead of a cell: the column's type name.
        let type_names = ["Int8", "Timestamp", "Date32", "Decimal", "List"];
        let mut failures = Vec::new();
        for (file, format, rows, values) in cases {
            let data = std::fs::read(format!("{dir}/{file}")).unwrap();
            match convert_tabular(format, "JSON", &data) {
                Err(e) => failures.push(format!("{file} -> JSON: {e}")),
                Ok(out) => {
                    let text = String::from_utf8(out.bytes).unwrap();
                    if out.row_count != rows {
                        failures.push(format!("{file}: {} rows, want {rows}", out.row_count));
                    }
                    for v in values.iter().filter(|v| !text.contains(**v)) {
                        failures.push(format!("{file} -> JSON lacks {v:?}"));
                    }
                    for t in type_names.iter().filter(|t| text.contains(**t)) {
                        failures.push(format!("{file} -> JSON prints type name {t:?}"));
                    }
                }
            }
            // CSV has no nested types, yet a list column must not make the file unexportable.
            if let Err(e) = convert_tabular(format, "CSV", &data) {
                failures.push(format!("{file} -> CSV: {e}"));
            }
        }
        for f in &failures {
            println!("FAIL {f}");
        }
        assert!(failures.is_empty(), "{} interop failures", failures.len());
    }
}
