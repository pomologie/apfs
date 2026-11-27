use std::{env, fs, io::Read};

use apfs_container::{Container, LookupOptions, OpenOptions};

const IMAGE_BYTES: u64 = 128 << 20;

fn main() -> Result<(), Box<dyn std::error::Error>> {
	let path = env::args_os().nth(1).ok_or("expected a fresh APFS image")?;
	let file = fs::File::open(path)?;
	let metadata = file.metadata()?;
	if !metadata.is_file() || metadata.len() != IMAGE_BYTES {
		return Err("expected a regular 128 MiB image".into());
	}
	let mut image = Vec::new();
	file.take(IMAGE_BYTES + 1).read_to_end(&mut image)?;
	assert_eq!(image.len() as u64, IMAGE_BYTES);
	let source = image.as_slice();
	let automatic = Container::open(source, OpenOptions::default()).expect("automatic checkpoint");
	let checkpoint = automatic.superblock();
	let xid = checkpoint.object.transaction;
	let exact = Container::open_at(source, OpenOptions::default(), xid).expect("exact checkpoint");
	assert_eq!(exact.superblock(), checkpoint);
	assert_eq!(exact.descriptor(), automatic.descriptor());
	assert_eq!(exact.mappings(), automatic.mappings());
	assert!(!automatic.mappings().is_empty());
	assert!(automatic.diagnostics().is_empty() && exact.diagnostics().is_empty());
	let ring = &checkpoint.descriptors;
	println!(
		"checkpoint {} {} {} {} {} {} {} {} {}",
		checkpoint.geometry.block_bytes(),
		checkpoint.geometry.block_count(),
		xid.0,
		automatic.descriptor().0,
		ring.blocks,
		ring.index,
		ring.length,
		ring.next,
		automatic.mappings().len()
	);
	let volumes = automatic
		.volumes(LookupOptions::default())
		.expect("volume table");
	assert_eq!(
		volumes,
		exact
			.volumes(LookupOptions::default())
			.expect("exact volume table")
	);
	assert_eq!(volumes.len(), 1);
	let volume = &volumes[0].superblock;
	print!("volume ");
	for byte in volume.uuid {
		print!("{byte:02x}");
	}
	println!(" {}", volume.name);
	Ok(())
}
