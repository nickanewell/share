use axum::{
    Json,
    extract::Path,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use serde::{Deserialize, Serialize};
use std::{borrow::Cow, time::SystemTime};

use crate::note::{Note, NoteInfo, generate_id};
use crate::store;
use crate::{config, lock::SharedState};

use super::NotePublic;

pub fn now() -> u32 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs() as u32
}

#[derive(Deserialize)]
pub struct OneNoteParams {
    id: String,
}

pub async fn preview(Path(OneNoteParams { id }): Path<OneNoteParams>) -> Response {
    let note = store::get(&id);

    match note {
        Ok(Some(n)) => (StatusCode::OK, Json(NoteInfo { meta: n.meta })).into_response(),
        Ok(None) => (StatusCode::NOT_FOUND).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

#[derive(Serialize, Deserialize)]
struct CreateResponse {
    id: String,
}

const FILE_FORMAT_HEADER: &str = "x-cryptgeon-file-format";

#[derive(Deserialize)]
struct FileEnvelopeHeader<'a> {
    #[serde(borrow)]
    format: Cow<'a, str>,
    version: f64,
}

fn reader_needs_file_format_update(contents: &str, headers: &HeaderMap) -> bool {
    let mut advertised_formats = headers.get_all(FILE_FORMAT_HEADER).iter();
    if advertised_formats.next().is_some_and(|value| value == "2")
        && advertised_formats.next().is_none()
    {
        return false;
    }

    // Legacy file arrays and text ciphertext do not use this object envelope.
    if !contents.trim_start().starts_with('{') {
        return false;
    }

    // Borrow the small format field and skip unknown fields, including ciphertext.
    // Do not deserialize the encrypted payload into an owned String or JSON Value.
    // Fail closed for malformed object envelopes: JavaScript accepts duplicate
    // fields using the last value, while serde rejects them as ambiguous.
    serde_json::from_str::<FileEnvelopeHeader<'_>>(contents).map_or(true, |header| {
        // Match the JSON number semantics used by the browser and CLI readers.
        header.format == "cryptgeon-files" && header.version == 2.0
    })
}

pub async fn create(Json(mut n): Json<Note>) -> Response {
    // let mut n = note.into_inner();
    let id = generate_id();
    // let bad_req = HttpResponse::BadRequest().finish();
    if n.views == None && n.expiration == None {
        return (
            StatusCode::BAD_REQUEST,
            "At least views or expiration must be set",
        )
            .into_response();
    }
    if !*config::ALLOW_ADVANCED {
        n.views = Some(1);
        n.expiration = None;
    }
    match n.views {
        Some(v) => {
            if v > *config::MAX_VIEWS || v < 1 {
                return (StatusCode::BAD_REQUEST, "Invalid views").into_response();
            }
            n.expiration = None; // views overrides expiration
        }
        _ => {}
    }
    match n.expiration {
        Some(e) => {
            if e > *config::MAX_EXPIRATION || e < 1 {
                return (StatusCode::BAD_REQUEST, "Invalid expiration").into_response();
            }
            let expiration = now() + (e * 60);
            n.expiration = Some(expiration);
        }
        _ => {}
    }
    match store::set(&id.clone(), &n.clone()) {
        Ok(_) => (StatusCode::OK, Json(CreateResponse { id })).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

pub async fn delete(
    Path(OneNoteParams { id }): Path<OneNoteParams>,
    state: axum::extract::State<SharedState>,
    headers: HeaderMap,
) -> Response {
    let _guard = state.locks.lock(&id).await;

    let note = store::get(&id);
    match note {
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
        Ok(None) => (StatusCode::NOT_FOUND).into_response(),
        Ok(Some(note)) => {
            if reader_needs_file_format_update(&note.contents, &headers) {
                return (
                    StatusCode::UPGRADE_REQUIRED,
                    "Update your Cryptgeon reader to open this file note; the note has not been consumed.",
                )
                    .into_response();
            }
            let mut changed = note.clone();
            if changed.views == None && changed.expiration == None {
                return (StatusCode::BAD_REQUEST).into_response();
            }
            match changed.views {
                Some(v) => {
                    changed.views = Some(v - 1);
                    let id = id.clone();
                    if v <= 1 {
                        match store::del(&id) {
                            Err(e) => {
                                return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string())
                                    .into_response();
                            }
                            _ => {}
                        }
                    } else {
                        match store::set(&id, &changed.clone()) {
                            Err(e) => {
                                return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string())
                                    .into_response();
                            }
                            _ => {}
                        }
                    }
                }
                _ => {}
            }

            let n = now();
            match changed.expiration {
                Some(e) => {
                    if e < n {
                        match store::del(&id.clone()) {
                            Ok(_) => return (StatusCode::BAD_REQUEST).into_response(),
                            Err(e) => {
                                return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string())
                                    .into_response();
                            }
                        }
                    }
                }
                _ => {}
            }

            return (
                StatusCode::OK,
                Json(NotePublic {
                    contents: changed.contents,
                    meta: changed.meta,
                }),
            )
                .into_response();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{FILE_FORMAT_HEADER, FileEnvelopeHeader, reader_needs_file_format_update};
    use axum::http::{HeaderMap, HeaderValue};
    use std::borrow::Cow;

    const V2_NOTE: &str = r#"{"format":"cryptgeon-files","version":2,"ciphertext":"encrypted"}"#;

    #[test]
    fn version_two_notes_require_the_exact_reader_capability() {
        let mut headers = HeaderMap::new();
        assert!(reader_needs_file_format_update(V2_NOTE, &headers));

        for value in ["1", "3", "unknown", "2, 3", ""] {
            headers.insert(FILE_FORMAT_HEADER, HeaderValue::from_str(value).unwrap());
            assert!(reader_needs_file_format_update(V2_NOTE, &headers));
        }

        headers.insert(FILE_FORMAT_HEADER, HeaderValue::from_static("2"));
        assert!(!reader_needs_file_format_update(V2_NOTE, &headers));
        headers.append(FILE_FORMAT_HEADER, HeaderValue::from_static("3"));
        assert!(reader_needs_file_format_update(V2_NOTE, &headers));
    }

    #[test]
    fn legacy_text_arrays_and_other_objects_do_not_require_a_new_reader() {
        let headers = HeaderMap::new();
        for contents in [
            "encrypted text ciphertext",
            r#"[{"name":"legacy.txt","contents":"encrypted"}]"#,
            r#"["cryptgeon-files",2]"#,
            r#"{"format":"other-format","version":2}"#,
            r#"{"format":"cryptgeon-files","version":1}"#,
            r#"{"format":"cryptgeon-files","version":3}"#,
        ] {
            assert!(!reader_needs_file_format_update(contents, &headers));
        }
    }

    #[test]
    fn malformed_object_envelopes_require_an_updated_reader() {
        let mut headers = HeaderMap::new();
        for contents in [
            "{",
            r#"{"format":"cryptgeon-files","version":2"#,
            r#"{"format":"cryptgeon-files"}"#,
            r#"{"version":2}"#,
            r#"{"format":null,"version":2}"#,
            r#"{"format":"cryptgeon-files","version":"2"}"#,
            r#"{"format":"other","format":"cryptgeon-files","version":2,"ciphertext":"encrypted"}"#,
            r#"{"format":"cryptgeon-files","version":1,"version":2,"ciphertext":"encrypted"}"#,
        ] {
            headers.clear();
            assert!(reader_needs_file_format_update(contents, &headers));
            headers.insert(FILE_FORMAT_HEADER, HeaderValue::from_static("2"));
            assert!(!reader_needs_file_format_update(contents, &headers));
        }
    }

    #[test]
    fn json_equivalent_format_and_version_values_are_detected() {
        let contents =
            r#"{"format":"cryptgeon\u002dfiles","version":2.0,"ciphertext":"encrypted"}"#;
        assert!(reader_needs_file_format_update(contents, &HeaderMap::new()));
    }

    #[test]
    fn large_ciphertext_is_skipped_while_the_format_is_borrowed() {
        let contents = format!(
            r#"{{"ciphertext":"{}","format":"cryptgeon-files","version":2}}"#,
            "x".repeat(10 * 1024 * 1024)
        );
        let header: FileEnvelopeHeader<'_> = serde_json::from_str(&contents).unwrap();
        assert!(matches!(header.format, Cow::Borrowed("cryptgeon-files")));
        assert!(reader_needs_file_format_update(
            &contents,
            &HeaderMap::new()
        ));
    }
}
