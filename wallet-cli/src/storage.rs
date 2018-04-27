use std::path::{PathBuf, Path};
use std::{fs, io};
use std::fs::OpenOptions;

use wallet_crypto::util::hex::{encode};
use wallet_crypto::util::hex::{decode};

use rcw;

use rand;

const HASH_SIZE : usize = 32;

pub type BlockHash = [u8;HASH_SIZE];
pub type PackHash = [u8;HASH_SIZE];

#[derive(Clone)]
pub struct Storage {
    pub root_path: PathBuf,
    pub blk_type: String, // example "mainnet" or "testnet"
}

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone, Copy)]
pub enum StorageFileType {
    Pack, Index, Blob, Tag
}

impl Storage {
    pub fn init(root: PathBuf, blk_type: String) -> io::Result<Self> {
        let storage = Storage { root_path: root, blk_type: blk_type };

        fs::create_dir_all(storage.get_filetype_dir(StorageFileType::Blob))?;
        fs::create_dir_all(storage.get_filetype_dir(StorageFileType::Index))?;
        fs::create_dir_all(storage.get_filetype_dir(StorageFileType::Pack))?;
        fs::create_dir_all(storage.get_filetype_dir(StorageFileType::Tag))?;

        Ok(storage)
    }

    pub fn get_path(&self) -> PathBuf {
        let mut p = self.root_path.clone();
        p.push(&self.blk_type);
        p
    }
    pub fn get_filetype_dir(&self, ft: StorageFileType) -> PathBuf {
        let mut p = self.get_path();
        match ft {
            StorageFileType::Pack => p.push("pack/"),
            StorageFileType::Index => p.push("index/"),
            StorageFileType::Blob => p.push("blob/"),
            StorageFileType::Tag => p.push("tag/"),
        }
        p
    }
    pub fn get_pack_filepath(&self, packhash: &PackHash) -> PathBuf {
        let mut p = self.get_filetype_dir(StorageFileType::Pack);
        p.push(encode(packhash));
        p
    }
    pub fn get_index_filepath(&self, packhash: &PackHash) -> PathBuf {
        let mut p = self.get_filetype_dir(StorageFileType::Index);
        p.push(encode(packhash));
        p
    }
    pub fn get_blob_filepath(&self, blockhash: &BlockHash) -> PathBuf {
        let mut p = self.get_filetype_dir(StorageFileType::Blob);
        p.push(encode(blockhash));
        p
    }
    pub fn get_tag_filepath<P: AsRef<Path>>(&self, s: P) -> PathBuf {
        let mut p = self.get_filetype_dir(StorageFileType::Tag);
        p.push(s);
        p
    }

    pub fn list_indexes(&self) -> Vec<PackHash> {
        let mut packs = Vec::new();
        let p = self.get_filetype_dir(StorageFileType::Index);
        for entry in fs::read_dir(p).unwrap() {
            let entry = entry.unwrap();
            if entry.file_type().unwrap().is_file() {
                let path = entry.file_name().into_string().unwrap();
                let mut packref = [0;HASH_SIZE];
                let v = decode(path.as_ref());
                if v.len() == 32 {
                    packref.clone_from_slice(&v[..]);
                    packs.push(packref);
                }

            }
        }
        packs
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
        // here we consider that the rename is atomic, which might depends on filesystem
        fs::rename(&self.path, path)
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
    TmpFile::create(storage.get_filetype_dir(filetype)).unwrap()
}

pub mod tag {
    use std::fs;
    use std::io::{Write,Read};

    pub fn write(storage: &super::Storage, name: &str, content: &[u8]) {
        let mut tmp_file = super::tmpfile_create_type(storage, super::StorageFileType::Tag);
        tmp_file.file.write_all(content).unwrap();
        tmp_file.render_permanent(&storage.get_tag_filepath(name));
    }

    pub fn read(storage: &super::Storage, name: &str) -> Option<Vec<u8>> {
        if ! exist(storage, name) { return None; }
        let mut content = Vec::new();
        let path = storage.get_tag_filepath(name);
        let mut file = fs::File::open(path).unwrap();
        file.read_to_end(&mut content).unwrap();
        Some(content)
    }

    pub fn exist(storage: &super::Storage, name: &str) -> bool {
        let p = storage.get_tag_filepath(name);
        p.as_path().exists()
    }
}

pub mod blob {
    use std::fs;
    use std::io::{Write,Read};

    pub fn write(storage: &super::Storage, hash: &super::BlockHash, block: &[u8]) {
        let mut tmp_file = super::tmpfile_create_type(storage, super::StorageFileType::Blob);
        tmp_file.file.write_all(block).unwrap();

        // finalize
        let path = storage.get_blob_filepath(&hash);
        tmp_file.render_permanent(&path);
    }

    pub fn read(storage: &super::Storage, hash: &super::BlockHash) -> Vec<u8> {
        let mut content = Vec::new();
        let path = storage.get_blob_filepath(&hash);
        
        let mut file = fs::File::open(path).unwrap();
        file.read_to_end(&mut content).unwrap();
        content
    }

    pub fn exist(storage: &super::Storage, hash: &super::BlockHash) -> bool {
        let p = storage.get_blob_filepath(hash);
        p.as_path().exists()
    }
}

pub mod pack {
    // a pack file is:
    //
    // MAGIC (8 Bytes)
    // #ENTRIES (8 Bytes)
    // 0-PADDING (16 Bytes)
    // FANOUT (256*8 bytes)
    // BLOCK HASHES present in this pack ordered lexigraphically (#ENTRIES * 32 bytes)
    // OFFSET of BLOCK in the same order as BLOCK_HASHES (#ENTRIES * 8 bytes)

    use super::{TmpFile};

    use std::iter::repeat;
    use std::io::SeekFrom;
    use std::io::{Write,Read,Seek};
    use std::fs;
    use storage::rcw::blake2b;
    use storage::rcw::digest::Digest;

    const MAGIC : &[u8] = b"ADAPACK1";
    const OFF_SIZE : usize = 8;

    const IDX_OFS_FANOUT : u64 = 32;
    const IDX_OFS_HASHES : u64 = IDX_OFS_FANOUT+256*8;

    type Offset = u64;
    type Size = u64;
    type IndexOffset = u64;

    type Entry = (super::BlockHash, Size);

    pub struct Fanout([u64;256]);
    pub struct FanoutStart(u64);
    pub struct FanoutNb(u64);

    impl Fanout {
        pub fn get_class_nb_by_hash(&self, hash: &super::BlockHash) -> u64 {
            match hash[0] as usize {
                0 => self.0[0],
                c => self.0[c] - self.0[c-1]
            }
        }
        pub fn get_class_nb(&self, class: u8) -> u64 {
            match class as usize {
                0 => self.0[0],
                c => self.0[c] - self.0[c-1]
            }
        }
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
    }

    fn write_size(buf: &mut [u8], sz: Size) {
        buf[0] = (sz >> 56) as u8;
        buf[1] = (sz >> 48) as u8;
        buf[2] = (sz >> 40) as u8;
        buf[3] = (sz >> 32) as u8;
        buf[4] = (sz >> 24) as u8;
        buf[5] = (sz >> 16) as u8;
        buf[6] = (sz >> 8) as u8;
        buf[7] = sz as u8;
    }
    fn read_size(buf: &[u8]) -> Size {
        ((buf[0] as u64) << 56)
          | ((buf[1] as u64) << 48)
          | ((buf[2] as u64) << 40)
          | ((buf[3] as u64) << 32)
          | ((buf[4] as u64) << 24)
          | ((buf[5] as u64) << 16)
          | ((buf[6] as u64) << 8)
          | ((buf[7] as u64))
    }

    fn file_read_size(mut file: &fs::File) -> u64 {
        let mut buf = [0u8;8];
        file.read_exact(&mut buf).unwrap();
        read_size(&buf)
    }

    fn file_read_hash(mut file: &fs::File) -> super::BlockHash {
        let mut buf = [0u8;super::HASH_SIZE];
        file.read_exact(&mut buf).unwrap();
        buf
    }

    pub fn create_index(storage: &super::Storage, index: &Index) -> super::TmpFile {
        let mut tmpfile = super::tmpfile_create_type(storage, super::StorageFileType::Index);
        let mut hdr_buf = [0u8;32];
        let entries = index.hashes.len();

        assert!(entries == index.offsets.len());

        hdr_buf[0..8].clone_from_slice(&MAGIC[..]);
        write_size(&mut hdr_buf[8..16], entries as u64);

        // write 32 bytes:
        // * magic (8 bytes)
        // * number of entries (8 bytes)
        // * 16 bytes of 0 padding
        tmpfile.write_all(&hdr_buf).unwrap();

        // write fanout
        let mut fanout = [0u64;256];
        for &hash in index.hashes.iter() {
            let ofs = hash[0] as usize;
            fanout[ofs] = fanout[ofs]+1;
        }

        let mut fanout_buf = [0u8;256*8];
        let mut fanout_sum = 0;
        for i in 0..256 {
            let ofs = i * 8;
            let abs = fanout[i];
            fanout_sum += abs;
            write_size(&mut fanout_buf[ofs..ofs+8], fanout_sum);
        }
        tmpfile.file.write_all(&fanout_buf).unwrap();

        let mut sorted = Vec::with_capacity(entries);
        for i in 0..entries {
            sorted[i] = (index.hashes[i], index.offsets[i]);
        }
        sorted.sort_by(|a, b| a.0.cmp(&b.0));

        for &(hash,_) in sorted.iter() {
            tmpfile.file.write_all(&hash[..]).unwrap();
        }

        for &(_, ofs) in sorted.iter() {
            let mut buf = [0u8;8];
            write_size(&mut buf, ofs);
            tmpfile.file.write_all(&buf[..]).unwrap();
        }
        tmpfile
    }

    pub fn read_index_fanout(storage: &super::Storage, pack: &super::PackHash) -> Fanout {
        let mut file = fs::File::open(storage.get_index_filepath(pack)).unwrap();
        file.seek(SeekFrom::Start(IDX_OFS_FANOUT)).unwrap();
        let mut buf = [0u8;256*8];
        file.read_exact(&mut buf).unwrap();

        let mut fanout = [0u64;256]; 
        for i in 0..256 {
            let ofs = i*8;
            fanout[i] = read_size(&buf[ofs..ofs+8])
        }
        Fanout(fanout)
    }

    pub fn search_index(mut file: &fs::File, blk: &super::BlockHash, start_elements: FanoutStart, hier_elements: FanoutNb) -> Option<IndexOffset> {

        let start = IDX_OFS_HASHES;
        match hier_elements.0 {
            0 => None,
            1 => {
                let ofsElement = start_elements.0;
                let ofs = ofsElement * super::HASH_SIZE as u64;
                file.seek(SeekFrom::Start(IDX_OFS_HASHES + ofsElement)).unwrap();
                let hash = file_read_hash(file);
                if &hash == blk { Some(ofsElement) } else { None }
            },
            2 => {
                let start = start_elements.0;
                let ofsElement = start_elements.0;
                let ofs = ofsElement * super::HASH_SIZE as u64;
                file.seek(SeekFrom::Start(IDX_OFS_HASHES + ofsElement)).unwrap();
                let hash = file_read_hash(file);
                let hash2 = file_read_hash(file);
                if &hash == blk { Some(ofsElement) } else if &hash2 == blk { Some(ofsElement+1) } else { None }
            },
            n => {
                let start = start_elements.0;
                let end = start_elements.0 + n;
                let mut ofsElement = start;
                let ofs = ofsElement * super::HASH_SIZE as u64;
                file.seek(SeekFrom::Start(IDX_OFS_HASHES + ofsElement)).unwrap();
                while ofsElement < end {
                    let hash = file_read_hash(file);
                    if &hash == blk {
                        return Some(ofsElement)
                    }
                    ofsElement += 1
                }
                None
            },
        }
    }

/*
    pub fn read_headers(storage: &super::Storage, pack: &super::PackHash) -> Vec<Entry> {
        let mut v = vec![];
        //Storage.get_
        v
    }
    */

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

    pub fn read_block_at(mut file: fs::File, ofs: Offset) -> Vec<u8>{
        let mut sz_buf = [0u8;8];
        
        file.seek(SeekFrom::Start(ofs)).unwrap();
        file.read_exact(&mut sz_buf).unwrap();
        let sz = read_size(&sz_buf);
        let mut v : Vec<u8> = repeat(0).take(sz as usize).collect();
        file.read_exact(v.as_mut_slice()).unwrap();
        v
    }

    pub struct PackWriter {
        tmpfile: TmpFile,
        index: Index,
        pos: u64,
        hash_context: blake2b::Blake2b, // hash of all the content of blocks without length or padding
        storage: super::Storage,
    }

    impl PackWriter {
        pub fn init(storage: &super::Storage) -> Self {
            let tmpfile = TmpFile::create(storage.get_filetype_dir(super::StorageFileType::Pack)).unwrap();
            let idx = Index::new();
            let ctxt = blake2b::Blake2b::new(32);
            PackWriter
                { tmpfile: tmpfile, index: idx, pos: 0, storage: storage.clone(), hash_context: ctxt }
        }

        pub fn append(&mut self, blockhash: &super::BlockHash, block: &[u8]) {
            let len = block.len() as u64;
            let mut sz_buf = [0u8;8];
            write_size(&mut sz_buf, len);
            self.tmpfile.file.write_all(&sz_buf[..]).unwrap();
            self.tmpfile.file.write_all(block).unwrap();
            self.hash_context.input(block.clone()); // unfortunate cloning

            let pad = [0u8;7];
            let pad_bytes = if (len % 8) != 0 {
                                let pad_sz = 8 - len % 8;
                                self.tmpfile.file.write_all(&pad[0..pad_sz as usize]).unwrap();
                                pad_sz
                            } else { 0 };
            self.index.append(blockhash, self.pos);
            self.pos += 8 + len + pad_bytes;
        }

        pub fn finalize(&mut self) -> (super::PackHash, Index) {
            let mut packhash : super::PackHash = [0u8;super::HASH_SIZE];
            self.hash_context.result(&mut packhash);
            let path = self.storage.get_pack_filepath(&packhash);
            self.tmpfile.render_permanent(&path);
            (packhash, self.index.clone())
        }
    }
}
