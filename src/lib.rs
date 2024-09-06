#[cfg(all(feature = "v02", feature = "v03"))]
compile_error!("version 02 and 03 are not compatible");

mod model;