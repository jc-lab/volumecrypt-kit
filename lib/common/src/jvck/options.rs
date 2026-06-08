use crate::{VckError, VckResult};

/// Minimum size of a single replica region (Metadata block + vendor data).
pub const MIN_METADATA_SIZE: u32 = 128 * 1024;

/// Replica layout options chosen at attach/encryption time.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct JvckMetadataOptions {
    /// Number of replicas stored in the header region (volume start).
    /// Only new partitions can use a header (existing filesystems occupy the
    /// front sectors), so this is `0` for OS volumes and shrink-encrypted data
    /// volumes.
    pub use_header: u32,
    /// Number of replicas stored in the footer region (volume end).
    pub use_footer: u32,
    /// Size of one replica region in bytes, vendor data included. >= 128 KiB.
    pub metadata_size: u32,
}

impl JvckMetadataOptions {
    pub fn validate(&self) -> VckResult<()> {
        if self.metadata_size < MIN_METADATA_SIZE {
            return Err(VckError::ValidationFailed(
                "metadata_size must be at least 128 KiB",
            ));
        }
        if self.replica_count() == 0 {
            return Err(VckError::ValidationFailed(
                "use_header + use_footer must be >= 1",
            ));
        }
        Ok(())
    }

    pub fn replica_count(&self) -> u32 {
        self.use_header + self.use_footer
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_small_metadata_size() {
        let opt = JvckMetadataOptions {
            use_header: 0,
            use_footer: 2,
            metadata_size: 64 * 1024,
        };
        assert!(opt.validate().is_err());
    }

    #[test]
    fn rejects_zero_replicas() {
        let opt = JvckMetadataOptions {
            use_header: 0,
            use_footer: 0,
            metadata_size: MIN_METADATA_SIZE,
        };
        assert!(opt.validate().is_err());
    }

    #[test]
    fn accepts_valid_options() {
        let opt = JvckMetadataOptions {
            use_header: 0,
            use_footer: 2,
            metadata_size: MIN_METADATA_SIZE,
        };
        assert!(opt.validate().is_ok());
        assert_eq!(opt.replica_count(), 2);
    }
}
