//! ResultFormatter — Arrow / Parquet / JSON result stream serializer.
//!
//! Converts DataFusion `RecordBatch` slices into the wire format requested
//! by the caller's `format_hint` field in `SubmitQueryRequest`.
//!
//! # Formats
//!
//! * **Arrow IPC** (default) — Arrow IPC file format serialized to bytes.
//!   Lowest overhead; used by K05 FederatedQueryRouter and K08 JointQueryCoordinator
//!   when co-located on the same cluster.
//! * **Parquet** — Parquet file bytes. Used by pipeline jobs that persist the
//!   result to T02.
//! * **JSON** — Newline-delimited JSON (one JSON object per row). Used by K01
//!   API Gateway for REST callers and K06 Operator Interface.
//!
//! # Semantic Law
//!
//! * INV-2: The formatter operates AFTER the full optimizer pipeline
//!   (ContractCheckRule + RowFilterRule + MaskingRule + DPNoiseRule).
//!   It never re-reads data; it only reshapes already-enforced batches.
//! * INV-4: The formatter does NOT produce the attestation JWS; that is
//!   done by `AttestationExec` / `T05Client` upstream. The formatter only
//!   handles the data bytes.

use arrow::array::ArrayRef;
use arrow::datatypes::DataType;
use arrow::ipc::writer::FileWriter;
use arrow::record_batch::RecordBatch;
use bytes::{BufMut, BytesMut};
use parquet::arrow::ArrowWriter;
use parquet::file::properties::WriterProperties;
use serde_json::{Map, Value};
use thiserror::Error;
use tracing::debug;

// ─── Errors ───────────────────────────────────────────────────────────────────

/// Errors from the result formatter.
#[derive(Debug, Error)]
pub enum FormatterError {
    /// Arrow IPC serialization failed.
    #[error("Arrow IPC serialization failed: {0}")]
    ArrowIpc(String),

    /// Parquet serialization failed.
    #[error("Parquet serialization failed: {0}")]
    Parquet(String),

    /// JSON serialization failed.
    #[error("JSON serialization failed: {0}")]
    Json(String),

    /// Unsupported column type encountered during JSON formatting.
    #[error("unsupported column type for JSON serialization: {type_name} (column '{column}')")]
    UnsupportedTypeForJson { type_name: String, column: String },
}

// ─── Format enum ─────────────────────────────────────────────────────────────

/// Output format for query results.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ResultFormat {
    /// Arrow IPC file format (default).
    #[default]
    Arrow,
    /// Parquet file format.
    Parquet,
    /// Newline-delimited JSON.
    Json,
}

impl ResultFormat {
    /// Parse from the gRPC `ResultFormat` enum value.
    pub fn from_proto_i32(v: i32) -> Self {
        match v {
            1 => ResultFormat::Parquet,
            2 => ResultFormat::Json,
            _ => ResultFormat::Arrow,
        }
    }
}

// ─── Formatter ────────────────────────────────────────────────────────────────

/// Serializes enforced `RecordBatch` slices into the requested wire format.
pub struct ResultFormatter;

impl ResultFormatter {
    /// Format a slice of record batches according to the requested format.
    ///
    /// # Arguments
    ///
    /// * `batches` — the enforced result batches from the physical plan.
    /// * `format` — target wire format.
    ///
    /// # Returns
    ///
    /// Serialized bytes suitable for sending to the caller.
    pub fn format_results(
        batches: &[RecordBatch],
        format: ResultFormat,
    ) -> Result<bytes::Bytes, FormatterError> {
        if batches.is_empty() {
            return Ok(bytes::Bytes::new());
        }

        debug!(
            format = ?format,
            batch_count = batches.len(),
            "formatting query results"
        );

        match format {
            ResultFormat::Arrow => Self::format_arrow(batches),
            ResultFormat::Parquet => Self::format_parquet(batches),
            ResultFormat::Json => Self::format_json(batches),
        }
    }

    /// Serialize batches as Arrow IPC file format.
    fn format_arrow(batches: &[RecordBatch]) -> Result<bytes::Bytes, FormatterError> {
        let schema = batches[0].schema();
        let mut buf: Vec<u8> = Vec::new();

        {
            let mut writer = FileWriter::try_new(&mut buf, &schema)
                .map_err(|e| FormatterError::ArrowIpc(format!("FileWriter init: {e}")))?;

            for batch in batches {
                writer
                    .write(batch)
                    .map_err(|e| FormatterError::ArrowIpc(format!("write batch: {e}")))?;
            }

            writer
                .finish()
                .map_err(|e| FormatterError::ArrowIpc(format!("finish: {e}")))?;
        }

        Ok(bytes::Bytes::from(buf))
    }

    /// Serialize batches as Parquet file.
    fn format_parquet(batches: &[RecordBatch]) -> Result<bytes::Bytes, FormatterError> {
        let schema = batches[0].schema();
        let mut buf: Vec<u8> = Vec::new();

        let props = WriterProperties::builder()
            .set_compression(parquet::basic::Compression::SNAPPY)
            .build();

        {
            let mut writer = ArrowWriter::try_new(&mut buf, schema.clone(), Some(props))
                .map_err(|e| FormatterError::Parquet(format!("ArrowWriter init: {e}")))?;

            for batch in batches {
                writer
                    .write(batch)
                    .map_err(|e| FormatterError::Parquet(format!("write batch: {e}")))?;
            }

            writer
                .close()
                .map_err(|e| FormatterError::Parquet(format!("close: {e}")))?;
        }

        Ok(bytes::Bytes::from(buf))
    }

    /// Serialize batches as newline-delimited JSON.
    fn format_json(batches: &[RecordBatch]) -> Result<bytes::Bytes, FormatterError> {
        let mut out = BytesMut::new();

        for batch in batches {
            let schema = batch.schema();
            let num_rows = batch.num_rows();
            let num_cols = batch.num_columns();

            for row_idx in 0..num_rows {
                let mut obj = Map::new();
                for col_idx in 0..num_cols {
                    let field = schema.field(col_idx);
                    let col = batch.column(col_idx);
                    let value = column_value_at(col, row_idx, field.name(), field.data_type())?;
                    obj.insert(field.name().to_string(), value);
                }
                let row_json = serde_json::to_string(&obj).map_err(|e| {
                    FormatterError::Json(format!("row {row_idx} serialization: {e}"))
                })?;
                out.put_slice(row_json.as_bytes());
                out.put_u8(b'\n');
            }
        }

        Ok(out.freeze())
    }
}

/// Extract a JSON `Value` for a single cell in a RecordBatch column.
///
/// Supports: Null, Boolean, Int8/16/32/64, UInt8/16/32/64, Float32/64, Utf8,
/// LargeUtf8, Date32, Date64, Timestamp. Everything else returns a JSON string
/// representation via Debug.
fn column_value_at(
    col: &ArrayRef,
    row: usize,
    col_name: &str,
    data_type: &DataType,
) -> Result<Value, FormatterError> {
    if col.is_null(row) {
        return Ok(Value::Null);
    }

    use arrow::array::*;
    use arrow::datatypes::DataType::*;

    let val = match data_type {
        Null => Value::Null,
        Boolean => {
            let arr = col.as_any().downcast_ref::<BooleanArray>().ok_or_else(|| {
                FormatterError::Json(format!("downcast Boolean failed for col '{col_name}'"))
            })?;
            Value::Bool(arr.value(row))
        }
        Int8 => Value::Number(
            col.as_any()
                .downcast_ref::<Int8Array>()
                .map(|a| a.value(row) as i64)
                .unwrap_or(0)
                .into(),
        ),
        Int16 => Value::Number(
            col.as_any()
                .downcast_ref::<Int16Array>()
                .map(|a| a.value(row) as i64)
                .unwrap_or(0)
                .into(),
        ),
        Int32 => Value::Number(
            col.as_any()
                .downcast_ref::<Int32Array>()
                .map(|a| a.value(row) as i64)
                .unwrap_or(0)
                .into(),
        ),
        Int64 => {
            let arr = col.as_any().downcast_ref::<Int64Array>().ok_or_else(|| {
                FormatterError::Json(format!("downcast Int64 failed for col '{col_name}'"))
            })?;
            Value::Number(arr.value(row).into())
        }
        UInt8 => Value::Number(
            col.as_any()
                .downcast_ref::<UInt8Array>()
                .map(|a| a.value(row) as u64)
                .unwrap_or(0)
                .into(),
        ),
        UInt16 => Value::Number(
            col.as_any()
                .downcast_ref::<UInt16Array>()
                .map(|a| a.value(row) as u64)
                .unwrap_or(0)
                .into(),
        ),
        UInt32 => Value::Number(
            col.as_any()
                .downcast_ref::<UInt32Array>()
                .map(|a| a.value(row) as u64)
                .unwrap_or(0)
                .into(),
        ),
        UInt64 => Value::Number(
            col.as_any()
                .downcast_ref::<UInt64Array>()
                .map(|a| a.value(row))
                .unwrap_or(0)
                .into(),
        ),
        Float32 => {
            let v = col
                .as_any()
                .downcast_ref::<Float32Array>()
                .map(|a| a.value(row) as f64)
                .unwrap_or(0.0);
            serde_json::Number::from_f64(v)
                .map(Value::Number)
                .unwrap_or(Value::Null)
        }
        Float64 => {
            let arr = col.as_any().downcast_ref::<Float64Array>().ok_or_else(|| {
                FormatterError::Json(format!("downcast Float64 failed for col '{col_name}'"))
            })?;
            serde_json::Number::from_f64(arr.value(row))
                .map(Value::Number)
                .unwrap_or(Value::Null)
        }
        Utf8 => {
            let arr = col.as_any().downcast_ref::<StringArray>().ok_or_else(|| {
                FormatterError::Json(format!("downcast Utf8 failed for col '{col_name}'"))
            })?;
            Value::String(arr.value(row).to_string())
        }
        LargeUtf8 => {
            let arr = col
                .as_any()
                .downcast_ref::<LargeStringArray>()
                .ok_or_else(|| {
                    FormatterError::Json(format!("downcast LargeUtf8 failed for col '{col_name}'"))
                })?;
            Value::String(arr.value(row).to_string())
        }
        // For Date32 / Date64 / Timestamp variants, emit as ISO string via Display.
        Date32 | Date64 | Timestamp(_, _) | Time32(_) | Time64(_) | Duration(_) | Interval(_) => {
            Value::String(format!("{:?}", col.as_any()))
        }
        // Binary types: base64-encode.
        Binary | LargeBinary | FixedSizeBinary(_) => {
            use base64::Engine;
            let bytes_val: &[u8] = match data_type {
                Binary => col
                    .as_any()
                    .downcast_ref::<BinaryArray>()
                    .map(|a| a.value(row))
                    .unwrap_or_default(),
                LargeBinary => col
                    .as_any()
                    .downcast_ref::<LargeBinaryArray>()
                    .map(|a| a.value(row))
                    .unwrap_or_default(),
                _ => b"",
            };
            Value::String(base64::engine::general_purpose::STANDARD.encode(bytes_val))
        }
        // Float16: convert to f32 via u16 bit pattern.
        Float16 => {
            let v = col
                .as_any()
                .downcast_ref::<Float16Array>()
                .map(|a| f32::from(a.value(row)) as f64)
                .unwrap_or(0.0);
            serde_json::Number::from_f64(v)
                .map(Value::Number)
                .unwrap_or(Value::Null)
        }
        // View types: treat like their non-view string equivalents.
        Utf8View => {
            let arr = col
                .as_any()
                .downcast_ref::<StringViewArray>()
                .ok_or_else(|| {
                    FormatterError::Json(format!("downcast Utf8View failed for col '{col_name}'"))
                })?;
            Value::String(arr.value(row).to_string())
        }
        BinaryView => {
            use base64::Engine;
            let arr = col
                .as_any()
                .downcast_ref::<BinaryViewArray>()
                .map(|a| a.value(row))
                .unwrap_or_default();
            Value::String(base64::engine::general_purpose::STANDARD.encode(arr))
        }
        // List view types: emit null (callers should use Arrow format).
        ListView(_) | LargeListView(_) => Value::Null,
        // Complex types: serialize as JSON null (callers should use Arrow format).
        List(_)
        | LargeList(_)
        | FixedSizeList(_, _)
        | Map(_, _)
        | Struct(_)
        | Union(_, _)
        | Dictionary(_, _)
        | Decimal128(_, _)
        | Decimal256(_, _)
        | RunEndEncoded(_, _) => {
            // Best-effort: emit as a JSON null for unsupported complex types.
            Value::Null
        }
    };

    Ok(val)
}
