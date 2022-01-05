/*
 * Copyright 2021 OpenFlowLabs
 *
 */
use cloudconfig::CloudConfig;
use std::io::prelude::*;
use flate2::read::GzDecoder;
use std::io::BufReader;
use std::path::PathBuf;
use failure::Error;
use std::fs::File;
use crate::common::*;

pub mod cloudconfig;
pub mod networkconfig;
pub mod multiformat_deserialize;

pub fn read_user_data(log: &Logger, path: &PathBuf) -> Result<UserData, Error> {
    // Parse Multipart message from stream
    match read_gz_data(log, path) {
        Ok(data) => Ok(data),
        Err(err) => {
            match err.downcast::<UserDataError>() {
                Ok(uerr) => {
                    if uerr == UserDataError::NotGzData {
                        Ok(read_uncompressed(log, path)?)
                    } else {
                        Err(uerr)?
                    }
                }
                Err(oerr) => Err(oerr)
            }
        }
    }
}

fn read_gz_data(log: &Logger, path: &PathBuf) -> Result<UserData, Error> {
    let gzreader = GzDecoder::new(File::open(path)?);
    if None == gzreader.header() {
        return Err(UserDataError::NotGzData)?;
    }

    let mut reader = BufReader::new(gzreader);
    parse_user_data_multipart_stream::<BufReader<GzDecoder<File>>>(log, &mut reader)
}

fn read_uncompressed(log: &Logger, path: &PathBuf) -> Result<UserData, Error> {
    let mut reader = BufReader::new(File::open(path)?);
    parse_user_data_multipart_stream::<BufReader<File>>(log, &mut reader)
}

fn parse_user_data_multipart_stream<S: BufRead>(log: &Logger, stream: &mut S) -> Result<UserData, Error> {

    let mut buf = Vec::new();
    stream.read_to_end(&mut buf)?;

    let mail = mailparse::parse_mail(buf.as_slice())?;
    let mut data = UserData::default();
    for part in &mail.subparts {
        let body = part.get_body()?;
        parse_file_part(log, &mut data, part.ctype.mimetype.as_str(), &body)?;
    }

    let body = mail.get_body()?;
    parse_file_part(log, &mut data, &mail.headers[0].get_key(), &body)?;

    Ok(data)
}

fn parse_file_part(log: &Logger, d: &mut UserData, mime_type: &str, buf: &str) -> Result<(), Error> {
    match mime_type {
        "text/cloud-config" | "#cloud-config" => {
            let cc = serde_yaml::from_str::<CloudConfig>(buf)?;
            d.cloud_configs.push(cc);
        }
        "text/x-shellscript" => {
            d.scripts.push(buf.into())
        }
        _ => {
            info!(log, "unsupported mime type {}, skipping", mime_type);
        }
    }

    Ok(())
}

#[derive(Debug, Fail, PartialEq)]
enum UserDataError {
    #[fail(display = "format of file {} is not parseable", path)]
    InvalidFile{
        path: String,
    },
    #[fail(display = "file is not compressed")]
    NotGzData,
}

#[derive(Debug, Clone, Default, Eq, PartialEq)]
pub struct UserData {
    pub cloud_configs: Vec<CloudConfig>,
    pub scripts: Vec<String>,
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;
    use std::str::FromStr;
    use crate::userdata::UserData;
    use crate::common::init_log;

    #[test]
    fn multipart_parse() {
        let log = init_log();
        let res = crate::userdata::read_user_data(&log, &PathBuf::from_str("./sample_data/mime_message.txt").unwrap());
        let udata = res.unwrap();
        assert_ne!(udata, UserData::default());
    }

    #[test]
    fn userdata_parse() {
        let log = init_log();
        let res = crate::userdata::read_user_data(&log, &PathBuf::from_str("./sample_data/user-data").unwrap());
        let udata = res.unwrap();
        assert_ne!(udata, UserData::default());
    }
}
