//! This is a simple example to demonstrate the usage of this library.

fn main() -> Result<(), minreq::Error> {
    let response = minreq::get("https://example.com").send()?;
    println!("{}", response.as_str()?);
    Ok(())
}
