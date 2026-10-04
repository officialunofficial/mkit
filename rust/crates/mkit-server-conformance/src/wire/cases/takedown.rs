//! Minimal signed acceptance/denial contract; the runtime driver restarts between
//! the two phases. Preservation and legal-hold rehearsals remain separate.
use super::{CaseResult, Ctx, Failure, ensure, want_ok};
use crate::wire::client::{Rpc, STREAM_PROTO, UNARY_JSON, decode_stream, frame};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use buffa::Message as _;
use ed25519_dalek::{Signer as _, SigningKey};
use mkit_core::hash::{Hash, hash, to_hex, to_hex_bytes};
use mkit_transport_connect::generated::__buffa::oneof::issue_object_url_request::Target;
use mkit_transport_connect::generated::{
    DownloadPackRequest, DownloadPackResponse, IssueObjectUrlRequest, IssueObjectUrlResponse,
};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::sync::Arc;

const PRODUCER: &str = "takedown.contract";
const DATA: &[u8] = b"synthetic takedown payload";

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Saved {
    repository: String,
    private_repository: String,
    object: Hash,
    pack: Hash,
    takedown_id: String,
    token: String,
    ref_path: String,
}

fn scratch(ctx: &Ctx) -> Result<PathBuf, Failure> {
    let signer = ctx.v2_signer("repository-a")?;
    Ok(std::env::temp_dir().join(format!(
        "mkit-takedown-{}.json",
        to_hex(&hash(signer.public_key_hex().as_bytes()))
    )))
}

async fn admin(
    ctx: &Ctx,
    method: &str,
    value: serde_json::Value,
) -> Result<serde_json::Value, Failure> {
    let path = format!("/mkit.server.admin.v1.AdminService/{method}");
    let body = serde_json::to_vec(&value).map_err(|e| e.to_string())?;
    let crate::wire::WireAuth::AuthV2 { audience, .. } = &ctx.profile().auth else {
        return Err("admin fixture requires auth v2".into());
    };
    let created = ctx.server_now_ms();
    let expires = created + 60_000;
    let nonce = to_hex(&crate::wire::profile::random_bytes());
    let digest = format!("body:{}", to_hex(&hash(&body)));
    let canonical = format!(
        "mkit-admin:v1\noperator\n{audience}\n{path}\n{digest}\n{created}\n{expires}\n{nonce}"
    );
    let signature = SigningKey::from_bytes(&[0x77; 32]).sign(&hash(canonical.as_bytes()));
    let values = [
        "1".into(),
        "operator".into(),
        audience.clone(),
        created.to_string(),
        expires.to_string(),
        nonce,
        digest,
        to_hex_bytes(&signature.to_bytes()),
    ];
    let headers: Vec<_> = mkit_server::admin::HEADER_NAMES
        .into_iter()
        .zip(values)
        .map(|(name, value)| (name.into(), value))
        .collect();
    let reply = ctx.client().post(&path, UNARY_JSON, &headers, body).await?;
    ensure!(
        reply.status == 200,
        "signed admin {method}: HTTP {}",
        reply.status
    );
    ensure!(
        reply
            .headers
            .get("cache-control")
            .is_some_and(|h| h == "no-store"),
        "admin cache policy differs"
    );
    serde_json::from_slice(&reply.body).map_err(|e| Failure::Fail(format!("admin JSON: {e}")))
}

async fn reads(ctx: &Ctx, saved: &Saved, denied: bool) -> CaseResult {
    let object = format!("/{}/-/objects/{}", saved.repository, to_hex(&saved.object));
    for (kind, url) in [
        ("public object", object.clone()),
        ("public ref", saved.ref_path.clone()),
        (
            "private token",
            format!(
                "/{}/-/objects/{}?token={}",
                saved.private_repository,
                to_hex(&saved.object),
                saved.token
            ),
        ),
    ] {
        for method in ["GET", "HEAD"] {
            let reply = ctx.client().read(method, &url, &[]).await?;
            ensure!(
                reply.status == if denied { 404 } else { 200 },
                "takedown {kind} {method} denial={denied}: HTTP {}",
                reply.status
            );
            if denied {
                ensure!(
                    !reply.body.windows(DATA.len()).any(|bytes| bytes == DATA),
                    "denied read leaked file bytes"
                );
            }
            if !denied && method == "GET" {
                ensure!(reply.body.as_ref() == DATA, "live takedown file differs");
            }
            if method == "HEAD" {
                ensure!(reply.body.is_empty(), "HEAD leaked a body");
            }
        }
    }
    // The supported owner read is the signed transport download, including on
    // private repositories. HTTP object reads use public or token authority.
    let request = DownloadPackRequest {
        pack_id: Some(saved.pack.to_vec()),
        ..Default::default()
    };
    let body = frame(&request.encode_to_vec());
    let owner = ctx.v2_signer("repository-a")?;
    let mut envelope = owner.envelope(
        Rpc::DownloadPack.procedure(),
        crate::wire::sign::body_commitment(&body),
    );
    envelope.repository.clone_from(&saved.private_repository);
    envelope.digest = Some(to_hex(&hash(&body)));
    let reply = ctx
        .client()
        .post(
            Rpc::DownloadPack.procedure(),
            STREAM_PROTO,
            &owner.sign(&envelope).headers,
            body,
        )
        .await?;
    let stream = decode_stream::<DownloadPackResponse>(&reply)?;
    if denied {
        ensure!(
            stream.error.as_ref().is_some_and(|e| e.code == "not_found"),
            "owner download escaped takedown"
        );
        ensure!(
            stream.messages.is_empty(),
            "denied owner download emitted data before its error"
        );
    } else {
        ensure!(
            stream.error.is_none(),
            "owner download was not readable: {:?}",
            stream.error
        );
        ensure!(
            !Ctx::downloaded_bytes(&saved.pack, stream)?.is_empty(),
            "owner download was empty"
        );
    }
    Ok(())
}

async fn status(ctx: &Ctx, saved: &Saved) -> CaseResult {
    let value = admin(
        ctx,
        "GetTakedown",
        serde_json::json!({"takedownId":saved.takedown_id}),
    )
    .await?;
    let record = &value["takedown"];
    ensure!(
        record["takedownId"] == saved.takedown_id && record["repository"] == saved.repository,
        "admin identity differs"
    );
    ensure!(
        record["objectIds"] == serde_json::json!([STANDARD.encode(saved.object)]),
        "admin selectors differ"
    );
    ensure!(
        record["reasonToken"] == "manual" && record["level"] == "TAKEDOWN_LEVEL_CONTENT",
        "admin contract metadata differs"
    );
    ensure!(
        record["legalHold"] == false
            && record["preservationPurged"] == false
            && record["complete"] == false,
        "new takedown status differs"
    );
    Ok(())
}

pub(super) async fn contract(ctx: Ctx) -> CaseResult {
    let (pack, head, object) = super::portable_reads::single_file_pack(b"file.txt", DATA)?;
    let pack_id = hash(&pack);
    let (repository, _) = super::portable_reads::publish(&ctx, &pack, head).await?;
    let (private_repository, _) =
        super::portable_reads::publish_named(&ctx, &pack, head, "private-files", None).await?;
    let anonymous = ctx
        .client()
        .get(&format!(
            "/{private_repository}/-/objects/{}",
            to_hex(&object)
        ))
        .await?;
    ensure!(
        anonymous.status == 404,
        "takedown fixture requires private-by-default repositories"
    );
    let mint = IssueObjectUrlRequest {
        target: Some(Target::ObjectId(object.to_vec())),
        ..Default::default()
    };
    let signed = super::reads::signed_for(
        &ctx.v2_signer("repository-a")?,
        &private_repository,
        Rpc::IssueObjectUrl,
        &mint,
    );
    let minted: IssueObjectUrlResponse = want_ok(ctx.send(&signed).await?, "takedown URL token")?;
    let mut saved = Saved {
        ref_path: format!("/{repository}/-/{}/-/file.txt", ctx.head("async")),
        repository,
        private_repository,
        object,
        pack: pack_id,
        takedown_id: String::new(),
        token: minted.token.ok_or("missing takedown token")?,
    };
    reads(&ctx, &saved, false).await?;
    let reply = admin(&ctx, "Takedown", serde_json::json!({"operationId":"portable-contract", "repository":saved.repository,
        "objectIds":[STANDARD.encode(object)], "reason":"synthetic conformance", "reasonToken":"manual"})).await?;
    saved.takedown_id = reply["takedownId"]
        .as_str()
        .ok_or("missing takedown id")?
        .into();
    reads(&ctx, &saved, true).await?;
    status(&ctx, &saved).await?;
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    let mut file = options
        .open(scratch(&ctx)?)
        .map_err(|e| format!("takedown fixture capture: {e}"))?;
    serde_json::to_writer(&mut file, &saved).map_err(|e| e.to_string())?;
    ctx.set_note("signed takedown; public/ref/token/owner denial; token omitted".into());
    Ok(())
}

pub(super) async fn persisted(ctx: Ctx) -> CaseResult {
    let producer = Ctx::new(
        ctx.client().clone(),
        Arc::new(ctx.profile().clone()),
        PRODUCER,
    );
    let path = scratch(&producer)?;
    let file = std::fs::File::open(&path)
        .map_err(|e| format!("takedown producer must run before restart: {e}"))?;
    let saved: Saved = serde_json::from_reader(file).map_err(|e| e.to_string())?;
    reads(&producer, &saved, true).await?;
    status(&producer, &saved).await?;
    std::fs::remove_file(path).map_err(|e| e.to_string())?;
    ctx.set_note("persisted public/ref/token/owner denial and admin status; token omitted".into());
    Ok(())
}
