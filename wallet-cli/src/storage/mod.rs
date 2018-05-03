pub mod types;
pub mod config;
use std::path::{PathBuf, Path};
use std::{fs, io};
use std::fs::OpenOptions;

use wallet_crypto::util::hex::{encode};
use wallet_crypto::util::hex::{decode};
use std::collections::BTreeMap;

use rcw;

use rand;

use self::types::*;
use self::config::*;

const USE_COMPRESSION : bool = true;

pub struct Storage {
    config: StorageConfig,
    fanouts: BTreeMap<PackHash, pack::Fanout>,
}

impl Storage {
    pub fn init(cfg: &StorageConfig) -> io::Result<Self> {
        let mut fanouts = BTreeMap::new();

        fs::create_dir_all(cfg.get_filetype_dir(StorageFileType::Blob))?;
        fs::create_dir_all(cfg.get_filetype_dir(StorageFileType::Index))?;
        fs::create_dir_all(cfg.get_filetype_dir(StorageFileType::Pack))?;
        fs::create_dir_all(cfg.get_filetype_dir(StorageFileType::Tag))?;

        let packhashes = cfg.list_indexes();
        for p in packhashes.iter() {
            match pack::read_index_fanout(&cfg, p) {
                Err(_)     => {},
                Ok(fanout) => {
                    fanouts.insert(*p, fanout);
                }
            }
        }

        let storage = Storage { config: cfg.clone(), fanouts: fanouts };
        Ok(storage)
    }
}

pub struct TmpFile {
    file: fs::File,
    path: PathBuf,
}
impl TmpFile {
    pub fn create(mut path: PathBuf) -> io::Result<Self> {
        let v1 : u64 = rand::random();
        let v2 : u64 = rand::random();
        path.push(format!(".tmp.{}{}", v1, v2));

        OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .map(|file| TmpFile { file: file, path: path })
    }

    pub fn render_permanent(&self, path: &PathBuf) -> io::Result<()> {
        // NOTE: we need to consider what is being written, in a case of a tag we want rename
        // to error out correctly in every cases rename fail, however in a case of a hash, since the hash is suppose
        // to represent the same file, some error like EEXIST can be ignored, but some should be raised.
        // NOTE2: also we consider that the rename is atomic for the tmpfile abstraction to work correctly,
        // but it mostly depends on the actual filesystem. for most case it should be atomic.
        match fs::rename(&self.path, path) {
            _ => {},
        };
        Ok(())
    }
}
impl io::Read for TmpFile {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.file.read(buf)
    }
}
impl io::Write for TmpFile {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.file.write(buf)
    }
    fn flush(&mut self) -> io::Result<()> { self.file.flush() }
}

fn tmpfile_create_type(storage: &Storage, filetype: StorageFileType) -> TmpFile {
    TmpFile::create(storage.config.get_filetype_dir(filetype)).unwrap()
}

pub mod tag {
    use std::fs;
    use std::io::{Write,Read};
    use wallet_crypto::util::{hex};

    pub fn write(storage: &super::Storage, name: &str, content: &[u8]) {
        let mut tmp_file = super::tmpfile_create_type(storage, super::StorageFileType::Tag);
        tmp_file.file.write_all(hex::encode(content).as_bytes()).unwrap();
        tmp_file.render_permanent(&storage.config.get_tag_filepath(name)).unwrap();
    }

    pub fn read(storage: &super::Storage, name: &str) -> Option<Vec<u8>> {
        if ! exist(storage, name) { return None; }
        let mut content = Vec::new();
        let path = storage.config.get_tag_filepath(name);
        let mut file = fs::File::open(path).unwrap();
        file.read_to_end(&mut content).unwrap();
        String::from_utf8(content.clone()).ok()
            .and_then(|r| hex::decode(&r).ok())
            .or(Some(content))
    }

    pub fn exist(storage: &super::Storage, name: &str) -> bool {
        let p = storage.config.get_tag_filepath(name);
        p.as_path().exists()
    }
}

pub mod blob {
    use std::fs;
    use std::io::{Write,Read};
    use flate2::Compression;
    use flate2::write::DeflateEncoder;
    use flate2::write::DeflateDecoder;

    pub fn write(storage: &super::Storage, hash: &super::BlockHash, block: &[u8]) {
        let path = storage.config.get_blob_filepath(&hash);
        let mut tmp_file = super::tmpfile_create_type(storage, super::StorageFileType::Blob);
        if super::USE_COMPRESSION {
            let mut e = DeflateEncoder::new(Vec::new(), Compression::best());
            e.write_all(block).unwrap();
            let compressed_block = e.finish().unwrap();
            tmp_file.file.write_all(&compressed_block[..]).unwrap();
        } else {
            tmp_file.file.write_all(block).unwrap();
        }
        tmp_file.render_permanent(&path).unwrap();

    }

    pub fn read_raw(storage: &super::Storage, hash: &super::BlockHash) -> Vec<u8> {
        let mut content = Vec::new();
        let path = storage.config.get_blob_filepath(&hash);

        let mut file = fs::File::open(path).unwrap();
        file.read_to_end(&mut content).unwrap();
        content
    }

    pub fn read(storage: &super::Storage, hash: &super::BlockHash) -> Vec<u8> {
        let mut content = Vec::new();
        let path = storage.config.get_blob_filepath(&hash);

        let mut file = fs::File::open(path).unwrap();
        file.read_to_end(&mut content).unwrap();

        if super::USE_COMPRESSION {
            let mut writer = Vec::new();
            let mut deflater = DeflateDecoder::new(writer);
            deflater.write_all(&content[..]).unwrap();
            writer = deflater.finish().unwrap();
            writer
        } else {
            content
        }
    }

    pub fn exist(storage: &super::Storage, hash: &super::BlockHash) -> bool {
        let p = storage.config.get_blob_filepath(hash);
        p.as_path().exists()
    }

    pub fn remove(storage: &super::Storage, hash: &super::BlockHash) {
        let p = storage.config.get_blob_filepath(hash);
        match fs::remove_file(p) {
            Ok(()) => {},
            Err(_) => {},
        }
    }
}

#[derive(Clone, Debug)]
pub enum BlockLocation {
    Packed(PackHash, pack::IndexOffset),
    Loose,
}

pub fn block_location(storage: &Storage, hash: &BlockHash) -> Option<BlockLocation> {
    for (packref, fanout) in storage.fanouts.iter() {
        let (start, nb) = fanout.get_indexer_by_hash(hash);
        match nb {
            pack::FanoutNb(0) => {},
            _                 => {
                let idx_filepath = storage.config.get_index_filepath(packref);
                let mut idx_file = fs::File::open(idx_filepath).unwrap();
                match pack::search_index(&mut idx_file, hash, start, nb) {
                    None       => {},
                    Some(iloc) => return Some(BlockLocation::Packed(packref.clone(), iloc)),
                }
            }
        }
    }
    if blob::exist(storage, hash) {
        return Some(BlockLocation::Loose);
    }
    None
}

pub fn block_read_location(storage: &Storage, loc: &BlockLocation, hash: &BlockHash) -> Option<Vec<u8>> {
    match loc {
        BlockLocation::Loose                 => Some(blob::read(storage, hash)),
        BlockLocation::Packed(packref, iofs) => {
            match storage.fanouts.get(packref) {
                None         => { unreachable!(); },
                Some(fanout) => {
                    let idx_filepath = storage.config.get_index_filepath(packref);
                    let mut idx_file = fs::File::open(idx_filepath).unwrap();
                    let pack_offset = pack::resolve_index_offset(&mut idx_file, fanout, *iofs);
                    let pack_filepath = storage.config.get_pack_filepath(packref);
                    let mut pack_file = fs::File::open(pack_filepath).unwrap();
                    Some(pack::read_block_at(&mut pack_file, pack_offset))
                }
            }
        }
    }
}

pub fn block_read(storage: &Storage, hash: &BlockHash) -> Option<Vec<u8>> {
    match block_location(storage, hash) {
        None      => None,
        Some(loc) => block_read_location(storage, &loc, hash),
    }
}

// packing parameters
//
// optionally set the maximum number of blobs in this pack
// optionally set the maximum size in bytes of the pack file.
//            note that the limits is best effort, not strict.
pub struct PackParameters {
    pub limit_nb_blobs: Option<u32>,
    pub limit_size: Option<u64>,
    pub delete_blobs_after_pack: bool,
}

pub fn pack_blobs(storage: &mut Storage, params: &PackParameters) -> PackHash {
    let mut writer = pack::PackWriter::init(&storage.config);
    let block_hashes = storage.config.list_blob(params.limit_nb_blobs);
    let mut blob_packed = Vec::new();
    for bh in block_hashes.iter() {
        let blob = blob::read_raw(storage, bh);
        writer.append(bh, &blob[..]);
        blob_packed.push(bh);
        match params.limit_size {
            None => {},
            Some(sz) => {
                if writer.get_current_size() >= sz {
                    break
                }
            }
        }
    }

    let (packhash, index) = writer.finalize();

    let (fanout, tmpfile) = pack::create_index(storage, &index);
    tmpfile.render_permanent(&storage.config.get_index_filepath(&packhash)).unwrap();

    if params.delete_blobs_after_pack {
        for bh in blob_packed.iter() {
            blob::remove(storage, bh);
        }
    }

    // append to fanout
    storage.fanouts.insert(packhash, fanout);
    packhash
}

pub mod pack {
    // a pack file is:
    //
    // MAGIC (8 Bytes)
    // FANOUT (256*4 bytes)
    // BLOCK HASHES present in this pack ordered lexigraphically (#ENTRIES * 32 bytes)
    // OFFSET of BLOCK in the same order as BLOCK_HASHES (#ENTRIES * 8 bytes)

    use super::{TmpFile};

    use std::iter::repeat;
    use std::io::SeekFrom;
    use std::io;
    use std::io::{Write,Read,Seek};
    use std::fs;
    use storage::rcw::blake2b;
    use storage::rcw::digest::Digest;
    use storage::types::HASH_SIZE;

    const MAGIC : &[u8] = b"ADAPACK1";
    const MAGIC_SIZE : usize = 8;
    const OFF_SIZE : usize = 8;
    const SIZE_SIZE : usize = 4;
    const FANOUT_SIZE : usize = 256*SIZE_SIZE;

    const HEADER_SIZE : usize = MAGIC_SIZE + FANOUT_SIZE;

    type Offset = u64;
    type Size = u32;
    pub type IndexOffset = u32;

    pub struct Fanout([u32;256]);
    pub struct FanoutStart(u32);
    pub struct FanoutNb(pub u32);

    impl Fanout {
        /*
        pub fn get_class_nb_by_hash(&self, hash: &super::BlockHash) -> u32 {
            match hash[0] as usize {
                0 => self.0[0],
                c => self.0[c] - self.0[c-1]
            }
        }
        pub fn get_class_nb(&self, class: u8) -> u32 {
            match class as usize {
                0 => self.0[0],
                c => self.0[c] - self.0[c-1]
            }
        }
        */
        pub fn get_indexer_by_hash(&self, hash: &super::BlockHash) -> (FanoutStart, FanoutNb) {
            self.get_indexer_by_hier(hash[0])
        }

        pub fn get_indexer_by_hier(&self, hier: u8) -> (FanoutStart, FanoutNb) {
            match hier as usize {
                0 => (FanoutStart(0), FanoutNb(self.0[0])),
                c => {
                    let start = self.0[c-1];
                    (FanoutStart(start), FanoutNb(self.0[c] - start))
                },
            }
        }
        pub fn get_total(&self) -> FanoutNb {
            FanoutNb(self.0[255])
        }
    }

    fn write_size(buf: &mut [u8], sz: Size) {
        buf[0] = (sz >> 24) as u8;
        buf[1] = (sz >> 16) as u8;
        buf[2] = (sz >> 8) as u8;
        buf[3] = sz as u8;
    }
    fn read_size(buf: &[u8]) -> Size {
        ((buf[0] as Size) << 24)
          | ((buf[1] as Size) << 16)
          | ((buf[2] as Size) << 8)
          | (buf[3] as Size)
    }

    fn write_offset(buf: &mut [u8], sz: Offset) {
        buf[0] = (sz >> 56) as u8;
        buf[1] = (sz >> 48) as u8;
        buf[2] = (sz >> 40) as u8;
        buf[3] = (sz >> 32) as u8;
        buf[4] = (sz >> 24) as u8;
        buf[5] = (sz >> 16) as u8;
        buf[6] = (sz >> 8) as u8;
        buf[7] = sz as u8;
    }
    fn read_offset(buf: &[u8]) -> Offset {
        ((buf[0] as u64) << 56)
          | ((buf[1] as u64) << 48)
          | ((buf[2] as u64) << 40)
          | ((buf[3] as u64) << 32)
          | ((buf[4] as u64) << 24)
          | ((buf[5] as u64) << 16)
          | ((buf[6] as u64) << 8)
          | ((buf[7] as u64))
    }

    fn file_read_offset(mut file: &fs::File) -> Offset {
        let mut buf = [0u8;OFF_SIZE];
        file.read_exact(&mut buf).unwrap();
        read_offset(&buf)
    }

    fn file_read_hash(mut file: &fs::File) -> super::BlockHash {
        let mut buf = [0u8;HASH_SIZE];
        file.read_exact(&mut buf).unwrap();
        buf
    }

    pub fn create_index(storage: &super::Storage, index: &Index) -> (Fanout, super::TmpFile) {
        let mut tmpfile = super::tmpfile_create_type(storage, super::StorageFileType::Index);
        let mut hdr_buf = [0u8;HEADER_SIZE];

        let entries = index.hashes.len();

        assert!(entries == index.offsets.len());

        hdr_buf[0..8].clone_from_slice(&MAGIC[..]);

        // write fanout to hdr_buf
        let fanout = {
            let mut fanout_abs = [0u32;256];
            for &hash in index.hashes.iter() {
                let ofs = hash[0] as usize;
                fanout_abs[ofs] = fanout_abs[ofs]+1;
            }
            let mut fanout_sum = 0;
            let mut fanout_incr = [0u32;256];
            for i in 0..256 {
                fanout_sum += fanout_abs[i];
                fanout_incr[i] = fanout_sum;
            }

            for i in 0..256 {
                let ofs = 8 + i * SIZE_SIZE; /* start at 8, because 0..8 is the magic */
                write_size(&mut hdr_buf[ofs..ofs+SIZE_SIZE], fanout_incr[i]);
            }
            Fanout(fanout_incr)
        };
        tmpfile.file.write_all(&hdr_buf).unwrap();

        let mut sorted = Vec::with_capacity(entries);
        for i in 0..entries {
            sorted.push((index.hashes[i], index.offsets[i]));
        }
        sorted.sort_by(|a, b| a.0.cmp(&b.0));

        for &(hash,_) in sorted.iter() {
            tmpfile.file.write_all(&hash[..]).unwrap();
        }

        for &(_, ofs) in sorted.iter() {
            let mut buf = [0u8;8];
            write_offset(&mut buf, ofs);
            tmpfile.file.write_all(&buf[..]).unwrap();
        }
        (fanout, tmpfile)
    }

    pub fn open_index(storage_config: &super::StorageConfig, pack: &super::PackHash) -> fs::File {
        fs::File::open(storage_config.get_index_filepath(pack)).unwrap()
    }

    pub fn dump_index(storage_config: &super::StorageConfig, pack: &super::PackHash) -> io::Result<(Fanout, Vec<super::BlockHash>)> {
        let mut file = open_index(storage_config, pack);
        let fanout = index_get_header(&mut file)?;

        let mut v = Vec::new();
        let FanoutNb(total) = fanout.get_total();

        file.seek(SeekFrom::Start(HEADER_SIZE as u64)).unwrap();
        for _ in 0..total {
            let h = file_read_hash(&mut file);
            v.push(h);
        }
        Ok((fanout, v))
    }

    pub fn index_get_header(mut file: &fs::File) -> io::Result<Fanout> {
        let mut hdr_buf = [0u8;HEADER_SIZE];

        file.read_exact(&mut hdr_buf)?;
        if &hdr_buf[0..8] != MAGIC {
            return Err(io::Error::last_os_error());
        }

        let mut fanout = [0u32;256]; 
        for i in 0..256 {
            let ofs = 8+i*4;
            fanout[i] = read_size(&hdr_buf[ofs..ofs+SIZE_SIZE])
        }
        Ok(Fanout(fanout))
    }

    pub fn read_index_fanout(storage_config: &super::StorageConfig, pack: &super::PackHash) -> io::Result<Fanout> {
        let mut file = open_index(storage_config, pack);
        index_get_header(&mut file)
    }

    pub fn search_index(mut file: &fs::File, blk: &super::BlockHash, start_elements: FanoutStart, hier_elements: FanoutNb) -> Option<IndexOffset> {
        match hier_elements.0 {
            0 => None,
            1 => {
                let ofs_element = start_elements.0;
                let ofs = ofs_element as u64 * HASH_SIZE as u64;
                file.seek(SeekFrom::Start(HEADER_SIZE as u64 + ofs)).unwrap();
                let hash = file_read_hash(file);
                if &hash == blk { Some(ofs_element) } else { None }
            },
            2 => {
                let ofs_element = start_elements.0;
                let ofs = ofs_element as u64 * HASH_SIZE as u64;
                file.seek(SeekFrom::Start(HEADER_SIZE as u64 + ofs)).unwrap();
                let hash = file_read_hash(file);
                let hash2 = file_read_hash(file);
                if &hash == blk { Some(ofs_element) } else if &hash2 == blk { Some(ofs_element+1) } else { None }
            },
            n => {
                let start = start_elements.0;
                let end = start_elements.0 + n;
                let mut ofs_element = start;
                let ofs = ofs_element as u64 * HASH_SIZE as u64;
                file.seek(SeekFrom::Start(HEADER_SIZE as u64 + ofs)).unwrap();
                while ofs_element < end {
                    let hash = file_read_hash(file);
                    if &hash == blk {
                        return Some(ofs_element)
                    }
                    ofs_element += 1
                }
                None
            },
        }
    }

    pub fn resolve_index_offset(mut file: &fs::File, fanout: &Fanout, index_offset: IndexOffset) -> Offset {
        let FanoutNb(total) = fanout.get_total();
        let ofs = HEADER_SIZE as u64 + HASH_SIZE as u64 * total as u64 + OFF_SIZE as u64 * index_offset as u64;
        file.seek(SeekFrom::Start(ofs)).unwrap();
        file_read_offset(&mut file)
    }

    #[derive(Clone)]
    pub struct Index {
        pub hashes: Vec<super::BlockHash>,
        pub offsets: Vec<Offset>,
    }

    impl Index {
        pub fn new() -> Self {
            Index { hashes: Vec::new(), offsets: Vec::new() }
        }

        pub fn append(&mut self, hash: &super::BlockHash, offset: Offset) {
            self.hashes.push(hash.clone());
            self.offsets.push(offset);
        }
    }

    use flate2::write::DeflateDecoder;

    pub fn read_block_at(mut file: &fs::File, ofs: Offset) -> Vec<u8>{
        let mut sz_buf = [0u8;SIZE_SIZE];
        
        file.seek(SeekFrom::Start(ofs)).unwrap();
        file.read_exact(&mut sz_buf).unwrap();

        let sz = read_size(&sz_buf);
        let mut v : Vec<u8> = repeat(0).take(sz as usize).collect();
        file.read_exact(v.as_mut_slice()).unwrap();
        if super::USE_COMPRESSION {
            let mut writer = Vec::new();
            let mut deflater = DeflateDecoder::new(writer);
            deflater.write_all(&v[..]).unwrap();
            writer = deflater.finish().unwrap();
            writer
        } else {
            v
        }
    }

    // A Writer for a specific pack that accumulate some numbers for reportings,
    // index, blobs_hashes for index creation (in finalize)
    pub struct PackWriter {
        tmpfile: TmpFile,
        index: Index,
        pub nb_blobs: u32,
        pub pos: Offset, // offset in bytes of the current position (double as the current size of the pack)
        hash_context: blake2b::Blake2b, // hash of all the content of blocks without length or padding
        storage_config: super::StorageConfig,
    }

    impl PackWriter {
        pub fn init(cfg: &super::StorageConfig) -> Self {
            let tmpfile = TmpFile::create(cfg.get_filetype_dir(super::StorageFileType::Pack)).unwrap();
            let idx = Index::new();
            let ctxt = blake2b::Blake2b::new(32);
            PackWriter
                { tmpfile: tmpfile, index: idx, pos: 0, nb_blobs: 0, storage_config: cfg.clone(), hash_context: ctxt }
        }

        pub fn get_current_size(&self) -> u64 {
            self.pos
        }

        pub fn get_current_number_of_blobs(&self) -> u32 {
            self.nb_blobs
        }

        pub fn append(&mut self, blockhash: &super::BlockHash, block: &[u8]) {
            let len = block.len() as Size;
            let mut sz_buf = [0u8;SIZE_SIZE];
            write_size(&mut sz_buf, len);
            self.tmpfile.file.write_all(&sz_buf[..]).unwrap();
            self.tmpfile.file.write_all(block).unwrap();
            self.hash_context.input(block.clone()); // unfortunate cloning

            let pad = [0u8;SIZE_SIZE-1];
            let pad_bytes = if (len % 4 as u32) != 0 {
                                let pad_sz = 4 - len % 4;
                                self.tmpfile.file.write_all(&pad[0..pad_sz as usize]).unwrap();
                                pad_sz
                            } else { 0 };
            self.index.append(blockhash, self.pos);
            self.pos += 4 + len as u64 + pad_bytes as u64;
            self.nb_blobs += 1;
        }

        pub fn finalize(&mut self) -> (super::PackHash, Index) {
            let mut packhash : super::PackHash = [0u8;HASH_SIZE];
            self.hash_context.result(&mut packhash);
            let path = self.storage_config.get_pack_filepath(&packhash);
            self.tmpfile.render_permanent(&path).unwrap();
            (packhash, self.index.clone())
        }
    }
}
