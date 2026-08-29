//! Incremental SQLite WAL replication using Litestream-compatible LTX v3.
//!
//! The capture connection is kept open for the lifetime of the replicator. It
//! disables SQLite auto-checkpointing, maintains Litestream's read lock, and
//! writes local L0 LTX segments from committed WAL frames. Uploads are ordered
//! and the remote position advances only after object-store writes complete.

use futures_util::TryStreamExt;
use object_store::{ObjectStore, ObjectStoreExt, PutMode, PutOptions, path::Path};
use rustyriver::{Db, ReplicaClient, TXID, ltx::FileInfo, restore};
use std::{
    collections::HashSet,
    path::Path as FsPath,
    sync::{
        Arc, Mutex as StdMutex,
        atomic::{AtomicU64, Ordering},
    },
};
use tokio::sync::Mutex;

const PAGE_HEADER_FLAG_SIZE: u16 = 1;

// superfly/ltx v0.5.2 changed page compression from one LZ4 frame per page to
// an LZ4 block prefixed by a big-endian compressed size. rustyriver 0.1 still
// uses the older internal representation, so translate only at the object-store
// boundary. The bytes persisted remotely are the current reference format.
pub fn encode_reference_ltx(legacy: &[u8]) -> anyhow::Result<Vec<u8>> {
    use rustyriver::ltx::{Crc64, HEADER_SIZE, PAGE_HEADER_SIZE, Trailer};
    let decoded = rustyriver::ltx::decode_file(legacy)?;
    let pages = rustyriver::ltx::decode_file_pages(legacy)?;
    let header = decoded.header.marshal();
    let mut out = header.to_vec();
    let mut crc = Crc64::new();
    crc.update(&header);
    let mut index = Vec::with_capacity(pages.len());
    for (pgno, page) in pages {
        let offset = out.len() as u64;
        let mut ph = [0u8; PAGE_HEADER_SIZE];
        ph[..4].copy_from_slice(&pgno.to_be_bytes());
        ph[4..].copy_from_slice(&PAGE_HEADER_FLAG_SIZE.to_be_bytes());
        let compressed = lz4_flex::block::compress(&page);
        let size = u32::try_from(compressed.len())?.to_be_bytes();
        out.extend_from_slice(&ph);
        out.extend_from_slice(&size);
        out.extend_from_slice(&compressed);
        crc.update(&ph);
        crc.update(&size);
        crc.update(&page);
        index.push((
            pgno,
            offset,
            (PAGE_HEADER_SIZE + 4 + compressed.len()) as u64,
        ));
    }
    let empty = [0u8; PAGE_HEADER_SIZE];
    out.extend_from_slice(&empty);
    crc.update(&empty);
    let index_start = out.len();
    for (pgno, offset, size) in index {
        append_uvarint(&mut out, pgno as u64);
        append_uvarint(&mut out, offset);
        append_uvarint(&mut out, size);
    }
    append_uvarint(&mut out, 0);
    crc.update(&out[index_start..]);
    let index_size = (out.len() - index_start) as u64;
    out.extend_from_slice(&index_size.to_be_bytes());
    crc.update(&index_size.to_be_bytes());
    crc.update(&decoded.trailer.post_apply_checksum.to_be_bytes());
    let trailer = Trailer {
        post_apply_checksum: decoded.trailer.post_apply_checksum,
        file_checksum: rustyriver::CHECKSUM_FLAG | crc.sum64(),
    };
    out.extend_from_slice(&trailer.marshal());
    debug_assert!(out.len() >= HEADER_SIZE);
    Ok(out)
}

pub fn decode_reference_ltx(reference: &[u8]) -> anyhow::Result<Vec<u8>> {
    use rustyriver::ltx::{Crc64, HEADER_SIZE, PAGE_HEADER_SIZE, TRAILER_SIZE, Trailer};
    if reference.len() < HEADER_SIZE + PAGE_HEADER_SIZE + 8 + TRAILER_SIZE {
        anyhow::bail!("LTX file is truncated");
    }
    let header = rustyriver::ltx::Header::parse(reference)?;
    header.validate()?;
    let trailer = Trailer::parse(&reference[reference.len() - TRAILER_SIZE..])?;
    let size_offset = reference.len() - TRAILER_SIZE - 8;
    let index_size =
        u64::from_be_bytes(reference[size_offset..size_offset + 8].try_into()?) as usize;
    let index_start = size_offset
        .checked_sub(index_size)
        .ok_or_else(|| anyhow::anyhow!("invalid LTX index"))?;
    let empty_offset = index_start
        .checked_sub(PAGE_HEADER_SIZE)
        .ok_or_else(|| anyhow::anyhow!("invalid LTX page terminator"))?;
    if reference.get(empty_offset..index_start) != Some(&[0u8; PAGE_HEADER_SIZE]) {
        anyhow::bail!("invalid LTX page terminator");
    }
    let mut crc = Crc64::new();
    crc.update(&reference[..HEADER_SIZE]);
    let mut cursor = index_start;
    let mut pages = Vec::new();
    loop {
        let pgno = take_uvarint(reference, &mut cursor)?;
        if pgno == 0 {
            break;
        }
        let offset = usize::try_from(take_uvarint(reference, &mut cursor)?)?;
        let entry_size = usize::try_from(take_uvarint(reference, &mut cursor)?)?;
        let end = offset
            .checked_add(entry_size)
            .ok_or_else(|| anyhow::anyhow!("invalid LTX page range"))?;
        let entry = reference
            .get(offset..end)
            .ok_or_else(|| anyhow::anyhow!("invalid LTX page range"))?;
        if entry.len() < PAGE_HEADER_SIZE + 4
            || u16::from_be_bytes(entry[4..6].try_into()?) & PAGE_HEADER_FLAG_SIZE == 0
        {
            anyhow::bail!("unsupported LTX page encoding");
        }
        let compressed_size = u32::from_be_bytes(entry[6..10].try_into()?) as usize;
        let compressed = entry
            .get(10..10 + compressed_size)
            .ok_or_else(|| anyhow::anyhow!("truncated LTX block"))?;
        let mut page = vec![0u8; header.page_size as usize];
        let written = lz4_flex::block::decompress_into(compressed, &mut page)?;
        if written != page.len() {
            anyhow::bail!("invalid LTX page size");
        }
        crc.update(&entry[..PAGE_HEADER_SIZE]);
        crc.update(&entry[PAGE_HEADER_SIZE..PAGE_HEADER_SIZE + 4]);
        crc.update(&page);
        pages.push((u32::try_from(pgno)?, page));
    }
    crc.update(&reference[empty_offset..index_start]);
    crc.update(&reference[index_start..size_offset + 8]);
    crc.update(&trailer.post_apply_checksum.to_be_bytes());
    if rustyriver::CHECKSUM_FLAG | crc.sum64() != trailer.file_checksum {
        anyhow::bail!("LTX checksum mismatch");
    }
    Ok(rustyriver::ltx::encode_file(
        &header,
        &pages,
        trailer.post_apply_checksum,
    )?)
}

fn append_uvarint(output: &mut Vec<u8>, mut value: u64) {
    while value >= 0x80 {
        output.push(value as u8 | 0x80);
        value >>= 7;
    }
    output.push(value as u8);
}

pub fn take_uvarint(input: &[u8], cursor: &mut usize) -> anyhow::Result<u64> {
    let mut value = 0u64;
    for shift in (0..=63).step_by(7) {
        let byte = *input
            .get(*cursor)
            .ok_or_else(|| anyhow::anyhow!("truncated LTX varint"))?;
        *cursor += 1;
        if shift == 63 && byte > 1 {
            anyhow::bail!("LTX varint overflow");
        }
        value |= u64::from(byte & 0x7f) << shift;
        if byte < 0x80 {
            return Ok(value);
        }
    }
    anyhow::bail!("LTX varint overflow")
}

pub struct ReplicaStoreClient {
    store: Arc<dyn ObjectStore>,
    path: String,
}

impl ReplicaStoreClient {
    pub fn new(store: Arc<dyn ObjectStore>, path: String) -> Self {
        Self { store, path }
    }

    fn key(&self, level: i32, min: TXID, max: TXID) -> Path {
        Path::from(format!(
            "{}/{level:04x}/{}",
            self.path,
            rustyriver::ltx::format_filename(min, max)
        ))
    }

    fn level_prefix(&self, level: i32) -> Path {
        Path::from(format!("{}/{level:04x}", self.path))
    }
}

fn replica_error(error: impl std::error::Error + Send + Sync + 'static) -> rustyriver::Error {
    rustyriver::Error::Other(Box::new(error))
}

#[async_trait::async_trait]
impl ReplicaClient for ReplicaStoreClient {
    fn type_name(&self) -> &str {
        "object_store"
    }

    async fn ltx_files(
        &self,
        level: i32,
        seek: TXID,
        _use_metadata: bool,
    ) -> rustyriver::Result<Vec<FileInfo>> {
        let mut files = self
            .store
            .list(Some(&self.level_prefix(level)))
            .try_collect::<Vec<_>>()
            .await
            .map_err(replica_error)?
            .into_iter()
            .filter_map(|object| {
                let name = object.location.filename()?;
                let (min_txid, max_txid) = rustyriver::ltx::parse_filename(name).ok()?;
                (min_txid >= seek).then_some(FileInfo {
                    level,
                    min_txid,
                    max_txid,
                    size: object.size as i64,
                    ..Default::default()
                })
            })
            .collect::<Vec<_>>();
        files.sort_by_key(|file| file.min_txid);
        Ok(files)
    }

    async fn open_ltx_file(
        &self,
        level: i32,
        min_txid: TXID,
        max_txid: TXID,
        offset: i64,
        size: i64,
    ) -> rustyriver::Result<Vec<u8>> {
        let bytes = self
            .store
            .get(&self.key(level, min_txid, max_txid))
            .await
            .map_err(replica_error)?
            .bytes()
            .await
            .map_err(replica_error)?;
        let bytes = decode_reference_ltx(&bytes)
            .map_err(|error| rustyriver::Error::Other(error.to_string().into()))?;
        let start = usize::try_from(offset).map_err(replica_error)?;
        let end = if size == 0 {
            bytes.len()
        } else {
            start
                .checked_add(usize::try_from(size).map_err(replica_error)?)
                .ok_or_else(|| rustyriver::Error::Other("LTX range overflow".into()))?
        };
        let slice = bytes
            .get(start..end)
            .ok_or_else(|| rustyriver::Error::Other("LTX range out of bounds".into()))?;
        Ok(slice.to_vec())
    }

    async fn write_ltx_file(
        &self,
        level: i32,
        min_txid: TXID,
        max_txid: TXID,
        data: &[u8],
    ) -> rustyriver::Result<FileInfo> {
        let data = encode_reference_ltx(data)
            .map_err(|error| rustyriver::Error::Other(error.to_string().into()))?;
        let key = self.key(level, min_txid, max_txid);
        let payload = bytes::Bytes::from(data.clone());
        match self
            .store
            .put_opts(
                &key,
                payload.clone().into(),
                PutOptions {
                    mode: PutMode::Create,
                    ..Default::default()
                },
            )
            .await
        {
            Ok(_) => {}
            Err(object_store::Error::AlreadyExists { .. }) => {
                let existing = self
                    .store
                    .get(&key)
                    .await
                    .map_err(replica_error)?
                    .bytes()
                    .await
                    .map_err(replica_error)?;
                if existing != payload {
                    return Err(rustyriver::Error::Other(
                        "immutable LTX object already exists with different bytes".into(),
                    ));
                }
            }
            Err(error) => return Err(replica_error(error)),
        }
        Ok(FileInfo {
            level,
            min_txid,
            max_txid,
            size: data.len() as i64,
            ..Default::default()
        })
    }

    async fn delete_ltx_files(&self, files: &[FileInfo]) -> rustyriver::Result<()> {
        for file in files {
            self.store
                .delete(&self.key(file.level, file.min_txid, file.max_txid))
                .await
                .map_err(replica_error)?;
        }
        Ok(())
    }

    async fn delete_all(&self) -> rustyriver::Result<()> {
        let objects = self
            .store
            .list(Some(&Path::from(self.path.clone())))
            .try_collect::<Vec<_>>()
            .await
            .map_err(replica_error)?;
        for object in objects {
            self.store
                .delete(&object.location)
                .await
                .map_err(replica_error)?;
        }
        Ok(())
    }
}

pub struct Replicator {
    store: Arc<dyn ObjectStore>,
    prefix: String,
    db_path: std::path::PathBuf,
    generation: u64,
    capture: StdMutex<Option<Db>>,
    upload: Mutex<()>,
    durable_txid: AtomicU64,
}

impl Replicator {
    pub fn new(
        store: Arc<dyn ObjectStore>,
        prefix: String,
        db_path: std::path::PathBuf,
        generation: u64,
    ) -> Self {
        Self {
            store,
            prefix,
            db_path,
            generation,
            capture: StdMutex::new(None),
            upload: Mutex::new(()),
            durable_txid: AtomicU64::new(0),
        }
    }

    fn generation_path(&self, generation: u64) -> String {
        format!("{}ltx/g{generation:020}", self.prefix)
    }

    pub fn client(&self, generation: u64) -> ReplicaStoreClient {
        ReplicaStoreClient {
            store: self.store.clone(),
            path: self.generation_path(generation),
        }
    }

    fn completion_key(&self, generation: u64) -> Path {
        Path::from(format!(
            "{}/complete.json",
            self.generation_path(generation)
        ))
    }

    /// Restore the highest generation whose complete initial chain was
    /// independently verified and committed. An interrupted initial upload can
    /// contain a valid but historical prefix, so mere LTX presence is not a
    /// sufficient restore criterion.
    pub async fn restore(&self) -> anyhow::Result<bool> {
        let base = Path::from(format!("{}ltx", self.prefix));
        let objects = self.store.list(Some(&base)).try_collect::<Vec<_>>().await?;
        let generations = objects
            .iter()
            .filter_map(|object| parse_generation(object.location.as_ref()))
            .collect::<HashSet<_>>();
        if generations.is_empty() {
            return Ok(false);
        }
        let mut completed = objects
            .iter()
            .filter(|object| object.location.as_ref().ends_with("/complete.json"))
            .filter_map(|object| parse_generation(object.location.as_ref()))
            .collect::<Vec<_>>();
        completed.sort_unstable();
        completed.dedup();
        let Some(generation) = completed.pop() else {
            anyhow::bail!(
                "LTX generations exist but none has a completion marker; explicit legacy recovery is required"
            );
        };

        let client = self.client(generation);
        anyhow::ensure!(
            !client.ltx_files(0, TXID::ZERO, false).await?.is_empty()
                || !client.ltx_files(9, TXID::ZERO, false).await?.is_empty(),
            "completed LTX generation {generation} has no restore chain"
        );
        remove_sqlite_files(&self.db_path)?;
        restore(&client, &self.db_path, TXID::ZERO).await?;
        Ok(true)
    }

    /// Make this generation eligible for future restores only after its full
    /// initial chain independently reconstructs a valid SQLite database.
    pub async fn commit_generation(&self) -> anyhow::Result<()> {
        let durable = self.durable_txid();
        anyhow::ensure!(durable > 0, "cannot commit an empty LTX generation");
        let directory = tempfile::Builder::new()
            .prefix("cog-ltx-commit-")
            .tempdir_in(self.db_path.parent().unwrap_or_else(|| FsPath::new(".")))?;
        let verified = directory.path().join("verified.sqlite");
        restore(&self.client(self.generation), &verified, TXID(durable)).await?;
        let connection = rusqlite::Connection::open(&verified)?;
        let integrity: String =
            connection.query_row("PRAGMA integrity_check", [], |row| row.get(0))?;
        anyhow::ensure!(
            integrity == "ok",
            "initial LTX chain failed integrity_check"
        );
        drop(connection);

        let marker = bytes::Bytes::from(serde_json::to_vec(&serde_json::json!({
            "version": 1,
            "generation": self.generation,
            "durable_txid": durable
        }))?);
        let key = self.completion_key(self.generation);
        match self
            .store
            .put_opts(
                &key,
                marker.clone().into(),
                PutOptions {
                    mode: PutMode::Create,
                    ..Default::default()
                },
            )
            .await
        {
            Ok(_) => Ok(()),
            Err(object_store::Error::AlreadyExists { .. }) => {
                let existing = self.store.get(&key).await?.bytes().await?;
                anyhow::ensure!(existing == marker, "generation completion marker changed");
                Ok(())
            }
            Err(error) => Err(error.into()),
        }
    }

    /// Capture every WAL transaction committed before this call and upload the
    /// resulting ordered L0 segments. Success is the durability proof used by
    /// the request path.
    pub async fn sync(&self) -> anyhow::Result<u64> {
        // Serialize complete passes, but never hold the SQLite-owning mutex
        // across an await. This is the same capture/stage/upload split celld
        // uses for its output gate.
        let _upload = self.upload.lock().await;
        let from = self.durable_txid.load(Ordering::SeqCst) + 1;
        let files = {
            let mut capture = self
                .capture
                .lock()
                .map_err(|_| anyhow::anyhow!("LTX capture lock poisoned"))?;
            validate_wal(&self.db_path)?;
            if capture.is_none() {
                *capture = Some(Db::open(&self.db_path)?);
            }
            let db = capture.as_mut().expect("capture initialized");
            db.sync()?;
            let through = db.pos()?.txid.0;
            (from..=through)
                .map(|txid| {
                    let path = db.ltx_path(0, TXID(txid), TXID(txid));
                    std::fs::read(path)
                        .map(|bytes| (txid, bytes))
                        .map_err(rustyriver::Error::from)
                })
                .collect::<rustyriver::Result<Vec<_>>>()?
        };

        let client = self.client(self.generation);
        for (txid, bytes) in files {
            client
                .write_ltx_file(0, TXID(txid), TXID(txid), &bytes)
                .await?;
            self.durable_txid.store(txid, Ordering::SeqCst);
        }
        let durable = self.durable_txid();
        if durable > 0 && durable.is_multiple_of(64) {
            self.compact_locked(&client, durable).await?;
        }
        Ok(durable)
    }

    /// Publish and verify a complete snapshot anchor, then remove only L0 and
    /// older snapshot objects that the verified anchor supersedes.
    pub async fn compact(&self) -> anyhow::Result<bool> {
        let _upload = self.upload.lock().await;
        let durable = self.durable_txid();
        if durable == 0 {
            return Ok(false);
        }
        self.compact_locked(&self.client(self.generation), durable)
            .await?;
        Ok(true)
    }

    async fn compact_locked(
        &self,
        client: &ReplicaStoreClient,
        durable: u64,
    ) -> anyhow::Result<()> {
        let directory = tempfile::Builder::new()
            .prefix("cog-ltx-compact-")
            .tempdir_in(self.db_path.parent().unwrap_or_else(|| FsPath::new(".")))?;
        let restored = directory.path().join("source.sqlite");
        restore(client, &restored, TXID(durable)).await?;
        let bytes = encode_snapshot(&restored, durable)?;
        client
            .write_ltx_file(9, TXID(1), TXID(durable), &bytes)
            .await?;

        // Prove the new remote anchor independently before deleting anything.
        let verified = directory.path().join("verified.sqlite");
        restore(client, &verified, TXID(durable)).await?;
        let connection = rusqlite::Connection::open(&verified)?;
        let integrity: String =
            connection.query_row("PRAGMA integrity_check", [], |row| row.get(0))?;
        anyhow::ensure!(
            integrity == "ok",
            "compacted replica failed integrity_check"
        );
        drop(connection);

        let l0 = client.ltx_files(0, TXID::ZERO, false).await?;
        let obsolete = l0
            .into_iter()
            .filter(|file| file.max_txid.0 <= durable)
            .collect::<Vec<_>>();
        client.delete_ltx_files(&obsolete).await?;
        let snapshots = client.ltx_files(9, TXID::ZERO, false).await?;
        let obsolete = snapshots
            .into_iter()
            .filter(|file| file.max_txid.0 < durable)
            .collect::<Vec<_>>();
        client.delete_ltx_files(&obsolete).await?;
        self.gc_old_generations(2).await?;
        Ok(())
    }

    async fn gc_old_generations(&self, keep: usize) -> anyhow::Result<()> {
        match self.store.head(&self.completion_key(self.generation)).await {
            Ok(_) => {}
            Err(object_store::Error::NotFound { .. }) => return Ok(()),
            Err(error) => return Err(error.into()),
        }
        let base = Path::from(format!("{}ltx", self.prefix));
        let objects = self.store.list(Some(&base)).try_collect::<Vec<_>>().await?;
        let mut generations = objects
            .iter()
            .filter_map(|object| parse_generation(object.location.as_ref()))
            .collect::<Vec<_>>();
        generations.sort_unstable();
        generations.dedup();
        // A stale owner must never collect another owner's objects.
        if generations.last().copied() != Some(self.generation) || generations.len() <= keep {
            return Ok(());
        }
        let retained = generations.split_off(generations.len() - keep);
        for object in objects {
            if parse_generation(object.location.as_ref())
                .is_some_and(|generation| !retained.contains(&generation))
            {
                self.store.delete(&object.location).await?;
            }
        }
        Ok(())
    }

    pub fn db_path(&self) -> &FsPath {
        &self.db_path
    }

    pub fn durable_txid(&self) -> u64 {
        self.durable_txid.load(Ordering::SeqCst)
    }

    pub fn pending_txids(&self) -> u64 {
        let local = self
            .capture
            .lock()
            .ok()
            .and_then(|mut capture| capture.as_mut().and_then(|db| db.pos().ok()))
            .map_or(0, |position| position.txid.0);
        local.saturating_sub(self.durable_txid())
    }
}

pub fn encode_snapshot(path: &FsPath, txid: u64) -> anyhow::Result<Vec<u8>> {
    let bytes = std::fs::read(path)?;
    anyhow::ensure!(
        bytes.len() >= 100 && &bytes[..16] == b"SQLite format 3\0",
        "invalid compacted SQLite database"
    );
    let raw_page_size = u16::from_be_bytes([bytes[16], bytes[17]]);
    let page_size = if raw_page_size == 1 {
        65_536
    } else {
        u32::from(raw_page_size)
    };
    anyhow::ensure!(bytes.len() % page_size as usize == 0, "partial SQLite page");
    let commit = (bytes.len() / page_size as usize) as u32;
    let lock_page = rustyriver::ltx::lock_pgno(page_size);
    let pages = bytes
        .chunks_exact(page_size as usize)
        .enumerate()
        .map(|(index, page)| (index as u32 + 1, page.to_vec()))
        .filter(|(pgno, _)| *pgno != lock_page)
        .collect::<Vec<_>>();
    let header = rustyriver::ltx::Header {
        version: rustyriver::ltx::VERSION,
        flags: rustyriver::ltx::HEADER_FLAG_NO_CHECKSUM,
        page_size,
        commit,
        min_txid: TXID(1),
        max_txid: TXID(txid),
        // Deterministic bytes make retries of an ambiguously acknowledged
        // immutable upload safely comparable.
        timestamp: 0,
        ..Default::default()
    };
    Ok(rustyriver::ltx::encode_file(&header, &pages, 0)?)
}

fn validate_wal(db_path: &FsPath) -> anyhow::Result<()> {
    let wal_path = std::path::PathBuf::from(format!("{}-wal", db_path.display()));
    let bytes = match std::fs::read(&wal_path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error.into()),
    };
    if bytes.is_empty() {
        return Ok(());
    }
    anyhow::ensure!(bytes.len() >= 32, "truncated SQLite WAL header");
    let magic = u32::from_be_bytes(bytes[..4].try_into()?);
    anyhow::ensure!(
        matches!(magic, 0x377f_0682 | 0x377f_0683),
        "invalid SQLite WAL magic"
    );
    let raw_page_size = u32::from_be_bytes(bytes[8..12].try_into()?);
    let page_size = if raw_page_size == 1 {
        65_536
    } else {
        raw_page_size
    };
    anyhow::ensure!(
        rustyriver::ltx::is_valid_page_size(page_size),
        "invalid SQLite WAL page size"
    );
    let frame_size = 24usize + page_size as usize;
    anyhow::ensure!(
        (bytes.len() - 32).is_multiple_of(frame_size),
        "truncated SQLite WAL frame"
    );
    if bytes.len() > 32 {
        let last_frame = bytes.len() - frame_size;
        let commit = u32::from_be_bytes(bytes[last_frame + 4..last_frame + 8].try_into()?);
        anyhow::ensure!(commit != 0, "SQLite WAL ends in an uncommitted transaction");
    }
    // SQLite's independent reader verifies frame salts/checksums while
    // materializing every page referenced by integrity_check.
    let connection =
        rusqlite::Connection::open_with_flags(db_path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)?;
    let integrity: String = connection.query_row("PRAGMA integrity_check", [], |row| row.get(0))?;
    anyhow::ensure!(integrity == "ok", "SQLite WAL failed integrity_check");
    Ok(())
}

pub fn parse_generation(key: &str) -> Option<u64> {
    key.split('/')
        .find_map(|part| part.strip_prefix('g')?.parse().ok())
}

fn remove_sqlite_files(path: &FsPath) -> anyhow::Result<()> {
    for suffix in ["", "-wal", "-shm"] {
        let candidate = if suffix.is_empty() {
            path.to_path_buf()
        } else {
            std::path::PathBuf::from(format!("{}{suffix}", path.display()))
        };
        match std::fs::remove_file(candidate) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
    }
    Ok(())
}
