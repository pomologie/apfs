extern crate std;

use super::{Profile, Superblock, Unsupported, check_profile};

const NATIVE: &[u8] = include_bytes!("../../tests/fixtures/native-block-0.bin");
// Apple File System Reference, Incompatible Container Feature Flags.
const VERSION_TWO_BIT: u32 = 1;

#[test]
fn required_feature_sets_match_typed_admission() {
	let (_, native) = Superblock::verified_profile(NATIVE).unwrap();
	let version_two = 1 << VERSION_TWO_BIT;
	assert_eq!(native.incompatible, version_two);
	let other_bits = (0..u64::BITS).filter(|&bit| bit != VERSION_TWO_BIT);
	let mut masks = 0;
	let mut observations = 0;
	for version in [0, version_two] {
		let singles = other_bits.clone().map(|bit| version | (1 << bit));
		let pairs = other_bits.clone().flat_map(|first| {
			other_bits
				.clone()
				.filter(move |&second| first < second)
				.map(move |second| version | (1 << first) | (1 << second))
		});
		for incompatible in core::iter::once(version).chain(singles).chain(pairs) {
			masks += 1;
			for has_keylocker in [false, true] {
				for fragmented_checkpoint_area in [false, true] {
					let mut profile = native;
					profile.incompatible = incompatible;
					profile.has_keylocker = has_keylocker;
					profile.fragmented_checkpoint_area = fragmented_checkpoint_area;
					assert_eq!(
						check_profile(profile),
						reference_admission(profile),
						"{profile:?}"
					);
					observations += 1;
				}
			}
		}
	}
	std::println!("\nAPFS bootstrap property typed-required-feature {masks} {observations}");
}

fn reference_admission(profile: Profile) -> Result<(), Unsupported> {
	let active_bits = (0..u64::BITS).filter(|&bit| (profile.incompatible >> bit) & 1 == 1);
	// The only allowed set contains version two. Storage qualifiers are considered
	// only once all required bits are understood, with keybag detection first.
	if !active_bits.eq([VERSION_TWO_BIT]) {
		return Err(Unsupported::IncompatibleFeatures(profile.incompatible));
	}
	match (profile.has_keylocker, profile.fragmented_checkpoint_area) {
		(true, _) => Err(Unsupported::Keylocker),
		(false, true) => Err(Unsupported::FragmentedCheckpointArea),
		(false, false) => Ok(()),
	}
}
