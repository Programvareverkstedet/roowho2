use clap::crate_version;

const fn long_version() -> &'static str {
    const DIRTY_SUFFIX: &str = match env!("GIT_DIRTY").as_bytes() {
        b"true" => " (dirty)",
        _ => "",
    };

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
        DIRTY_SUFFIX,
        "\n",
        "commit date: ",
        env!("GIT_COMMIT_DATE"),
        "\n\n",
        // "[features]\n",
        // "\n",
        // "\n",
        "[dependencies]\n",
        const_format::str_replace!(env!("DEPENDENCY_LIST"), ";", "\n")
    )
}

pub const LONG_VERSION: &str = long_version();
