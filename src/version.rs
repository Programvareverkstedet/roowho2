use clap::crate_version;

const fn long_version() -> &'static str {
    // macro_rules! feature {
    //     ($title:expr, $flag:expr) => {
    //         if cfg!(feature = $flag) {
    //             concat!($title, ": enabled")
    //         } else {
    //             concat!($title, ": disabled")
    //         }
    //     };
    // }

    const_format::concatcp!(
        crate_version!(),
        "\n",
        "build profile: ",
        env!("BUILD_PROFILE"),
        "\n",
        "commit: ",
        env!("GIT_COMMIT"),
        "\n\n",
        // "[features]\n",
        // "\n",
        // "\n",
        "[dependencies]\n",
        const_format::str_replace!(env!("DEPENDENCY_LIST"), ";", "\n")
    )
}

pub const LONG_VERSION: &str = long_version();
