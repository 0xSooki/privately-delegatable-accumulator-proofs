#[cfg(feature = "bilinear")]
pub mod bilinear_group;
#[cfg(feature = "class-group")]
pub mod class_group;
#[cfg(feature = "rsa")]
pub mod rsa_group;

#[cfg(feature = "bilinear")]
pub use bilinear_group::BilinearG1;
#[cfg(feature = "class-group")]
pub use class_group::ClassGroup;
#[cfg(feature = "rsa")]
pub use rsa_group::RsaGroup;
