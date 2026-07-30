fn get_git_commit() -> Option<String> {
    let repo = git2::Repository::discover(".").ok()?;
    let head = repo.head().ok()?;
    let commit = head.peel_to_commit().ok()?;
    Some(commit.id().to_string())
}

fn embed_build_time_info() {
    let commit = option_env!("GIT_COMMIT")
        .map(|s| s.to_string())
        .or_else(get_git_commit)
        .unwrap_or_else(|| "unknown".to_string());

    let build_profile = std::env::var("OUT_DIR")
        .unwrap_or_else(|_| "unknown".to_string())
        .split(std::path::MAIN_SEPARATOR)
        .nth_back(3)
        .unwrap_or("unknown")
        .to_string();

    let dependencies = build_info_build::build_script()
        .collect_runtime_dependencies(build_info_build::DependencyDepth::Depth(1))
        .build()
        .crate_info
        .dependencies
        .into_iter()
        .map(|dep| format!("{}: {}", dep.name, dep.version))
        .collect::<Vec<_>>()
        .join(";");

    println!("cargo:rustc-env=GIT_COMMIT={}", commit);
    println!("cargo:rustc-env=BUILD_PROFILE={}", build_profile);
    println!("cargo:rustc-env=DEPENDENCY_LIST={}", dependencies);
}

fn main() -> anyhow::Result<()> {
    embed_build_time_info();

    Ok(())
}
