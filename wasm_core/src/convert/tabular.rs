use apache_avro::{
    Codec as AvroCodec, Schema as AvroSchema, Writer as AvroWriter,
    schema::{Name as AvroName, RecordField, RecordFieldOrder, RecordSchema, UnionSchema},
    types::Value as AvroValue,
};
use arrow2::array::{
    Array, BooleanArray, Float32Array, Float64Array, Int32Array, Int64Array, MutableArray,
    MutableUtf8Array, Utf8Array,
};
use arrow2::chunk::Chunk;
use arrow2::datatypes::{DataType, Field, Schema};
use arrow2::io::avro::read as avro_read;
use arrow2::io::ipc::{read as ipc_read, write as ipc_write};
use arrow2::io::parquet::write::{
    CompressionOptions, RowGroupIterator, WriteOptions as ParquetWriteOptions,
};
use arrow2::io::parquet::write::{Encoding, Version};
use arrow2::io::parquet::{read as parquet_read, write as parquet_write};
use avro_schema::read::read_metadata as avro_read_metadata;
use serde_json::Value as JsonValue;
use std::collections::{BTreeMap, BTreeSet};
use std::io::Cursor;

type Batch = Chunk<Box<dyn Array>>;
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

/// Parse textual or binary tabular data into a schema plus batches. All values are
/// normalized to `Utf8` columns to keep type inference predictable across formats.
fn read_to_batches(fmt: TabularFormat, data: &[u8]) -> Result<(Schema, Vec<Batch>), String> {
    match fmt {
        TabularFormat::Json => parse_json_rows(data),
        TabularFormat::Csv | TabularFormat::Tsv => parse_delimited_rows(fmt, data),
        TabularFormat::Parquet => read_parquet_batches(data),
        TabularFormat::Avro => read_avro_batches(data),
        TabularFormat::ArrowIpc | TabularFormat::Feather => read_ipc_batches(data),
    }
}

fn parse_json_rows(data: &[u8]) -> Result<(Schema, Vec<Batch>), String> {
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
    json_values_to_batches(rows)
}

fn json_values_to_batches(rows: Vec<JsonValue>) -> Result<(Schema, Vec<Batch>), String> {
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
    build_batches_from_columns(names, columns)
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

fn parse_delimited_rows(fmt: TabularFormat, data: &[u8]) -> Result<(Schema, Vec<Batch>), String> {
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
    build_batches_from_columns(headers.iter().map(|s| s.to_string()).collect(), columns)
}

fn read_parquet_batches(data: &[u8]) -> Result<(Schema, Vec<Batch>), String> {
    let mut cursor = Cursor::new(data);
    let metadata = parquet_read::read_metadata(&mut cursor).map_err(err)?;
    let schema = parquet_read::infer_schema(&metadata).map_err(err)?;
    let row_groups = metadata.row_groups;
    let reader =
        parquet_read::FileReader::new(cursor, row_groups, schema.clone(), None, None, None);
    let mut batches = Vec::new();
    for batch in reader {
        let chunk = batch.map_err(err)?;
        batches.push(to_arc_batch(chunk));
    }
    Ok((schema, batches))
}

fn read_avro_batches(data: &[u8]) -> Result<(Schema, Vec<Batch>), String> {
    let mut reader = Cursor::new(data);
    let metadata = avro_read_metadata(&mut reader).map_err(err)?;
    let schema = avro_read::infer_schema(&metadata.record).map_err(err)?;
    let fields = schema.fields.clone();
    let mut reader = avro_read::Reader::new(reader, metadata, fields, None);
    let mut batches = Vec::new();
    for batch in reader.by_ref() {
        let chunk = batch.map_err(err)?;
        batches.push(to_arc_batch(chunk));
    }
    Ok((schema, batches))
}

fn read_ipc_batches(data: &[u8]) -> Result<(Schema, Vec<Batch>), String> {
    let mut cursor = Cursor::new(data);
    let metadata = ipc_read::read_file_metadata(&mut cursor).map_err(err)?;
    let mut reader = ipc_read::FileReader::new(cursor, metadata, None, None);
    let schema = reader.schema().clone();
    let mut batches = Vec::new();
    for batch in reader.by_ref() {
        let chunk = batch.map_err(err)?;
        batches.push(to_arc_batch(chunk));
    }
    Ok((schema, batches))
}

/// Convert a schema+batches into string-backed columns so we can export to any format.
fn normalize_to_utf8(schema: &Schema, batches: Vec<Batch>) -> Result<(Schema, Vec<Batch>), String> {
    let field_names: Vec<String> = schema.fields.iter().map(|f| f.name.clone()).collect();
    if batches.is_empty() {
        return Ok((utf8_schema_from(&field_names), Vec::new()));
    }
    let mut normalized_batches = Vec::with_capacity(batches.len());
    for batch in batches {
        let mut columns: ColumnData = field_names.iter().map(|_| Vec::new()).collect();
        for row_idx in 0..batch.len() {
            for (col_idx, array) in batch.arrays().iter().enumerate() {
                columns[col_idx].push(value_to_string(array.as_ref(), row_idx)?);
            }
        }
        let batch = build_batch_from_columns(field_names.clone(), columns)?;
        normalized_batches.push(batch);
    }
    Ok((utf8_schema_from(&field_names), normalized_batches))
}

fn value_to_string(array: &dyn Array, idx: usize) -> Result<Option<String>, String> {
    if array.is_null(idx) {
        return Ok(None);
    }
    match array.data_type() {
        DataType::Utf8 => {
            let arr = array
                .as_any()
                .downcast_ref::<Utf8Array<i32>>()
                .ok_or_else(|| "Invalid Utf8 array".to_string())?;
            Ok(arr.get(idx).map(|s| s.to_string()))
        }
        DataType::Boolean => {
            let arr = array
                .as_any()
                .downcast_ref::<BooleanArray>()
                .ok_or_else(|| "Invalid Bool array".to_string())?;
            Ok(Some(arr.value(idx).to_string()))
        }
        DataType::Int32 => {
            let arr = array
                .as_any()
                .downcast_ref::<Int32Array>()
                .ok_or_else(|| "Invalid Int32 array".to_string())?;
            Ok(Some(arr.value(idx).to_string()))
        }
        DataType::Int64 => {
            let arr = array
                .as_any()
                .downcast_ref::<Int64Array>()
                .ok_or_else(|| "Invalid Int64 array".to_string())?;
            Ok(Some(arr.value(idx).to_string()))
        }
        DataType::Float32 => {
            let arr = array
                .as_any()
                .downcast_ref::<Float32Array>()
                .ok_or_else(|| "Invalid Float32 array".to_string())?;
            Ok(Some(arr.value(idx).to_string()))
        }
        DataType::Float64 => {
            let arr = array
                .as_any()
                .downcast_ref::<Float64Array>()
                .ok_or_else(|| "Invalid Float64 array".to_string())?;
            Ok(Some(arr.value(idx).to_string()))
        }
        other => Ok(Some(format!("{other:?}"))),
    }
}

fn utf8_schema_from(fields: &[String]) -> Schema {
    Schema::from(
        fields
            .iter()
            .map(|name| Field::new(name.clone(), DataType::Utf8, true))
            .collect::<Vec<_>>(),
    )
}

fn build_batches_from_columns(
    fields: Vec<String>,
    columns: ColumnData,
) -> Result<(Schema, Vec<Batch>), String> {
    let batch = build_batch_from_columns(fields.clone(), columns)?;
    Ok((utf8_schema_from(&fields), vec![batch]))
}

fn build_batch_from_columns(_fields: Vec<String>, columns: ColumnData) -> Result<Batch, String> {
    let mut arrays: Vec<Box<dyn Array>> = Vec::with_capacity(columns.len());
    for col in columns {
        let mut builder = MutableUtf8Array::<i32>::new();
        for cell in col {
            match cell {
                Some(text) => builder.push(Some(text.as_str())),
                None => builder.push_null(),
            }
        }
        arrays.push(builder.as_box());
    }
    Chunk::try_new(arrays).map_err(err)
}

fn rows_from_batches(
    schema: &Schema,
    batches: Vec<Batch>,
) -> Result<(Vec<String>, ColumnData), String> {
    let (schema, normalized) = normalize_to_utf8(schema, batches)?;
    let field_names: Vec<String> = schema.fields.iter().map(|f| f.name.clone()).collect();
    if normalized.is_empty() {
        let len = field_names.len();
        return Ok((field_names, vec![Vec::new(); len]));
    }
    let mut merged_columns: Vec<Vec<Option<String>>> =
        field_names.iter().map(|_| Vec::new()).collect();
    for batch in normalized {
        for (idx, array) in batch.arrays().iter().enumerate() {
            let arr = array
                .as_any()
                .downcast_ref::<Utf8Array<i32>>()
                .ok_or_else(|| "Invalid Utf8 array".to_string())?;
            merged_columns[idx].extend(arr.iter().map(|v| v.map(|s| s.to_string())));
        }
    }
    Ok((field_names, merged_columns))
}

fn write_from_rows(
    fmt: TabularFormat,
    fields: Vec<String>,
    columns: ColumnData,
) -> Result<TabularResult, String> {
    match fmt {
        TabularFormat::Json => write_json(fields, columns),
        TabularFormat::Csv | TabularFormat::Tsv => write_delimited(fmt, fields, columns),
        TabularFormat::Parquet => write_parquet(fields, columns),
        TabularFormat::Avro => write_avro(fields, columns),
        TabularFormat::ArrowIpc | TabularFormat::Feather => write_ipc(fields, columns),
    }
}

fn to_arc_batch(batch: Chunk<Box<dyn Array>>) -> Batch {
    batch
}

fn write_json(fields: Vec<String>, columns: ColumnData) -> Result<TabularResult, String> {
    let mut rows = Vec::new();
    let row_count = columns.first().map(|c| c.len()).unwrap_or(0);
    for row_idx in 0..row_count {
        let mut map = serde_json::Map::new();
        for (field_idx, name) in fields.iter().enumerate() {
            let val = columns
                .get(field_idx)
                .and_then(|col| col.get(row_idx))
                .cloned()
                .flatten();
            map.insert(
                name.clone(),
                val.map(JsonValue::String).unwrap_or(JsonValue::Null),
            );
        }
        rows.push(JsonValue::Object(map));
    }
    let text = serde_json::to_string_pretty(&JsonValue::Array(rows)).map_err(err)?;
    let (mime, ext) = TabularFormat::Json.mime_and_ext();
    Ok(TabularResult {
        bytes: text.into_bytes(),
        mime_type: mime.to_string(),
        file_name: format!("converted.{ext}"),
        row_count: row_count as u64,
    })
}

fn write_delimited(
    fmt: TabularFormat,
    fields: Vec<String>,
    columns: ColumnData,
) -> Result<TabularResult, String> {
    let mut wtr = csv::WriterBuilder::new()
        .has_headers(true)
        .delimiter(fmt.delimiter().unwrap_or(b','))
        .from_writer(Vec::new());
    wtr.write_record(&fields).map_err(err)?;
    let row_count = columns.first().map(|c| c.len()).unwrap_or(0);
    for row_idx in 0..row_count {
        let mut row = Vec::with_capacity(fields.len());
        for col in &columns {
            row.push(col.get(row_idx).and_then(|v| v.clone()).unwrap_or_default());
        }
        wtr.write_record(&row).map_err(err)?;
    }
    wtr.flush().map_err(err)?;
    let bytes = wtr.into_inner().map_err(err)?;
    let (mime, ext) = fmt.mime_and_ext();
    Ok(TabularResult {
        bytes,
        mime_type: mime.to_string(),
        file_name: format!("converted.{ext}"),
        row_count: row_count as u64,
    })
}

fn make_utf8_batch(
    fields: &[String],
    columns: &ColumnData,
) -> Result<(Schema, Vec<Batch>), String> {
    let batch = build_batch_from_columns(fields.to_vec(), columns.to_vec())?;
    let schema = utf8_schema_from(fields);
    Ok((schema, vec![batch]))
}

fn write_ipc(fields: Vec<String>, columns: ColumnData) -> Result<TabularResult, String> {
    let (schema, batches) = make_utf8_batch(&fields, &columns)?;
    let mut out = Vec::new();
    let options = ipc_write::WriteOptions::default();
    let mut writer =
        ipc_write::FileWriter::try_new(&mut out, schema.clone(), None, options).map_err(err)?;
    for batch in batches {
        writer.write(&batch, None).map_err(err)?;
    }
    writer.finish().map_err(err)?;
    let (mime, ext) = TabularFormat::ArrowIpc.mime_and_ext();
    Ok(TabularResult {
        bytes: out,
        mime_type: mime.to_string(),
        file_name: format!("converted.{ext}"),
        row_count: columns.first().map(|c| c.len()).unwrap_or(0) as u64,
    })
}

fn write_parquet(fields: Vec<String>, columns: ColumnData) -> Result<TabularResult, String> {
    let (schema, batches) = make_utf8_batch(&fields, &columns)?;
    let options = ParquetWriteOptions {
        write_statistics: true,
        compression: CompressionOptions::Uncompressed,
        version: Version::V2,
        data_pagesize_limit: None,
    };
    let encodings: Vec<Vec<Encoding>> = schema
        .fields
        .iter()
        .map(|_| vec![Encoding::Plain])
        .collect();
    let row_groups =
        RowGroupIterator::try_new(batches.iter().cloned().map(Ok), &schema, options, encodings)
            .map_err(err)?;
    let mut out = Vec::new();
    let mut writer = parquet_write::FileWriter::try_new(&mut out, schema, options).map_err(err)?;
    for group in row_groups {
        writer.write(group.map_err(err)?).map_err(err)?;
    }
    writer.end(None).map_err(err)?;
    let (mime, ext) = TabularFormat::Parquet.mime_and_ext();
    Ok(TabularResult {
        bytes: out,
        mime_type: mime.to_string(),
        file_name: format!("converted.{ext}"),
        row_count: columns.first().map(|c| c.len()).unwrap_or(0) as u64,
    })
}

fn write_avro(fields: Vec<String>, columns: ColumnData) -> Result<TabularResult, String> {
    let union = UnionSchema::new(vec![AvroSchema::Null, AvroSchema::String]).map_err(err)?;
    let mut avro_fields = Vec::with_capacity(fields.len());
    for (idx, name) in fields.iter().enumerate() {
        avro_fields.push(RecordField {
            name: name.clone(),
            doc: None,
            aliases: None,
            default: Some(serde_json::Value::Null),
            schema: AvroSchema::Union(union.clone()),
            order: RecordFieldOrder::Ignore,
            position: idx,
            custom_attributes: BTreeMap::new(),
        });
    }
    let schema = RecordSchema {
        name: AvroName::new("AutoGenerated").map_err(err)?,
        aliases: None,
        doc: None,
        fields: avro_fields,
        lookup: fields
            .iter()
            .enumerate()
            .map(|(idx, name)| (name.clone(), idx))
            .collect(),
        attributes: BTreeMap::new(),
    };
    let schema = AvroSchema::Record(schema);

    let mut writer = AvroWriter::with_codec(&schema, Vec::new(), AvroCodec::Null);
    let row_count = columns.first().map(|c| c.len()).unwrap_or(0) as u64;
    for row_idx in 0..row_count as usize {
        let mut record = Vec::with_capacity(fields.len());
        for (col_idx, name) in fields.iter().enumerate() {
            let value = columns
                .get(col_idx)
                .and_then(|col| col.get(row_idx))
                .cloned()
                .flatten()
                .map(|s| AvroValue::Union(1, Box::new(AvroValue::String(s))))
                .unwrap_or_else(|| AvroValue::Union(0, Box::new(AvroValue::Null)));
            record.push((name.clone(), value));
        }
        writer
            .append(AvroValue::Record(record))
            .map_err(|e| e.to_string())?;
    }
    writer.flush().map_err(|e| e.to_string())?;
    let bytes = writer.into_inner().map_err(|e| e.to_string())?;
    let (mime, ext) = TabularFormat::Avro.mime_and_ext();
    Ok(TabularResult {
        bytes,
        mime_type: mime.to_string(),
        file_name: format!("converted.{ext}"),
        row_count,
    })
}

/// Main entry point used by wasm_bindgen wrapper.
pub fn convert_tabular(from: &str, to: &str, data: &[u8]) -> Result<TabularResult, String> {
    let from_fmt =
        TabularFormat::parse(from).ok_or_else(|| format!("Unsupported source format: {from}"))?;
    let to_fmt =
        TabularFormat::parse(to).ok_or_else(|| format!("Unsupported target format: {to}"))?;
    let (schema, batches) = read_to_batches(from_fmt, data)?;
    let (fields, columns) = rows_from_batches(&schema, batches)?;
    write_from_rows(to_fmt, fields, columns)
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
}
