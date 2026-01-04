fn main() {
    println!(
        "{:#?}",
        roowho2_lib::server::rwhod::generate_rwhod_status_update(),
    );
    println!(
        "{:#?}",
        roowho2_lib::server::rwhod::determine_relevant_interfaces(),
    );
}
