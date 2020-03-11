
use std::collections::HashMap;
use std::io::Write;


type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

pub fn fmthard(disk: &str, part: &str, tag: &str, flag: &str, start: u64,
    size: u64) -> Result<()>
{
    let cmd = format!("{}:{}:{}:{}:{}", part, tag, flag, start, size);
    let path = format!("/dev/rdsk/{}p0", disk);

    println!("fmthard -d {} {}", cmd, path);

    let output = std::process::Command::new("/usr/sbin/fmthard")
        .env_clear()
        .arg("-d").arg(cmd)
        .arg(path)
        .output()?;

    if !output.status.success() {
        return Err(format!("fmthard failure: {}",
            String::from_utf8_lossy(&output.stderr)).into());
    }

    Ok(())
}

pub fn zpool_expand(pool: &str, disk: &str) -> Result<()> {
    let output = std::process::Command::new("/sbin/zpool")
        .env_clear()
        .arg("online")
        .arg("-e")
        .arg(pool)
        .arg(disk)
        .output()?;

    if !output.status.success() {
        return Err(format!("zpool online failure: {}",
            String::from_utf8_lossy(&output.stderr)).into());
    }

    Ok(())
}

pub fn zpool_disk() -> Result<String> {
    let pool = "rpool";
    let output = std::process::Command::new("/sbin/zpool")
        .env_clear()
        .arg("list")
        .arg("-Hpv")
        .arg(pool)
        .output()?;

    if !output.status.success() {
        return Err(format!("zpool list failure: {}",
            String::from_utf8_lossy(&output.stderr)).into());
    }

    let out = String::from_utf8(output.stdout)?;
    let lines: Vec<_> = out.lines().collect();

    if lines.len() != 2 {
        return Err(format!("zpool list unexpected results: {:?}",
            lines).into());
    }

    let terms: Vec<_> = lines.iter().map(|l| {
        l.split('\t').collect::<Vec<_>>()
    }).collect();

    if terms[0].len() < 1 || terms[0][0] != pool ||
        terms[1].len() < 2 || terms[1][0] != "" {
        return Err(format!("zpool list unexpected results: {:?}",
            terms).into());
    }

    Ok(terms[1][1].to_string())
}

#[derive(Debug)]
struct Partition {
    id: String,
    tag: String,
    flags: String,
    sector_first: u64,
    sector_count: u64,
    sector_last: u64,
}

#[derive(Debug)]
struct Vtoc {
    sector_size: u64,
    sector_count: u64,
    partitions: HashMap<String, Partition>,
}

fn prtvtoc(disk: &str) -> Result<Vtoc> {
    let output = std::process::Command::new("/usr/sbin/prtvtoc")
        .env_clear()
        .arg(format!("/dev/dsk/{}", disk))
        .output()?;

    if !output.status.success() {
        return Err(format!("prtvtoc {} failure: {}", disk,
            String::from_utf8_lossy(&output.stderr)).into());
    }

    let out = String::from_utf8(output.stdout)?;
    let lines: Vec<_> = out.lines().collect();

    enum State {
        WaitingForDimensions,
        Dimensions,
        After,
    };
    let mut sectorsize: Option<u64> = None;
    let mut sectorcount: Option<u64> = None;
    let mut state = State::WaitingForDimensions;
    let mut parts: HashMap<String, Partition> = HashMap::new();

    for l in &lines {
        match state {
            State::WaitingForDimensions => {
                if l == &"* Dimensions:" {
                    state = State::Dimensions;
                }
            }
            State::Dimensions => {
                let t: Vec<_> = l.split_whitespace().collect();
                if t.len() == 3 && t[0] == "*" && t[2] == "bytes/sector" {
                    sectorsize = Some(t[1].parse()?);
                } else if t.len() == 3 && t[0] == "*" && t[2] == "sectors" {
                    sectorcount = Some(t[1].parse()?);
                } else if t.len() == 1 && t[0] == "*" {
                    state = State::After;
                }
            }
            State::After => {
                if l.starts_with("*") {
                    continue;
                }

                let t: Vec<_> = l.trim().split_whitespace().collect();

                parts.insert(t[0].to_string(), Partition {
                    id: t[0].to_string(),
                    tag: t[1].to_string(),
                    flags: t[2].to_string(),
                    sector_first: t[3].parse().unwrap(),
                    sector_count: t[4].parse().unwrap(),
                    sector_last: t[5].parse().unwrap(),
                });
            }
        }
    }

    if sectorcount.is_none() || sectorsize.is_none() {
        return Err(format!("prtvtoc {} bad output: {:?}", disk,
            lines).into());
    }

    Ok(Vtoc {
        sector_size: sectorsize.unwrap(),
        sector_count: sectorcount.unwrap(),
        partitions: parts,
    })
}

/**
 * Use the "expand" command in format(1M) to expand the GPT table into the
 * enlarged underlying volume.  This interface is clunky and unfortunate, but
 * I'm not currently aware of a better way.
 */
pub fn format_expand(disk: &str) -> Result<()> {
    /*
     * We need a temporary file with a list of commands for format(1M) to
     * execute using the "-f" option.
     */
    let tf = tempfile::NamedTempFile::new()?;
    println!("TEMP FILE: {:?}", tf.path().to_str().unwrap());
    let mut w = std::io::BufWriter::new(tf.as_file());
    w.write_all("partition\nexpand\nlabel\nquit\nquit\n".as_bytes())?;
    w.flush()?;

    let output = std::process::Command::new("/usr/sbin/format")
        .env_clear()
        .arg("-d").arg(disk)
        .arg("-f").arg(tf.path().to_str().unwrap())
        .output()?;

    if !output.status.success() {
        return Err(format!("format failure: {}",
            String::from_utf8_lossy(&output.stderr)).into());
    }

    Ok(())
}

/**
 * Check to see if this disk requires expansion at the GPT table level using
 * format(1M).
 */
pub fn should_expand(disk: &str) -> Result<bool> {
    let vtoc = prtvtoc(&disk)?;

    if vtoc.sector_size != 512 {
        return Err("only works with 512 byte sectors at the moment".into());
    }

    let reserved = vtoc.partitions.get("8").unwrap();
    if reserved.tag != "11" || reserved.sector_count != 16384 {
        return Err("slice 8 does not look like a regular reserved \
            partition".into());
    }

    /*
     * We expect the reserved partition to be situated near the end of the
     * volume.  I'm not currently sure where the magic number comes from.
     */
    let expected_ls = vtoc.sector_count - 34;

    if expected_ls < reserved.sector_last {
        return Err("cannot shrink partition".into());
    }

    Ok(expected_ls > reserved.sector_last)
}

/**
 * Check to see if the data slice should be grown to fill any unallocated space.
 */
pub fn grow_data_partition(disk: &str) -> Result<()> {
    let vtoc = prtvtoc(&disk)?;

    if vtoc.sector_size != 512 {
        return Err("only works with 512 byte sectors at the moment".into());
    }

    let reserved = vtoc.partitions.get("8").unwrap();
    if reserved.tag != "11" || reserved.sector_count != 16384 {
        return Err("slice 8 does not look like a regular reserved \
            partition".into());
    }

    let data = vtoc.partitions.get("1").unwrap();
    if data.tag != "4" {
        eprintln!("slice 1 does not look like a regular data partition");
        std::process::exit(1);
    }

    if data.sector_last >= reserved.sector_first - 1 {
        /*
         * The data partition is at least as large as expected, so do nothing.
         */
        println!("data partition growth not required");
        return Ok(());
    }

    let delta = reserved.sector_first - 1 - data.sector_last;

    println!("growing data partition...");
    fmthard(disk, &data.id, &data.tag, &data.flags,
        data.sector_first, data.sector_count + delta)?;
    println!("    ok");

    Ok(())
}
