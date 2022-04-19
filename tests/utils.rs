// Copyright 2020 Patrick Uiterwijk
//
// Licensed under the EUPL-1.2-or-later
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      https://joinup.ec.europa.eu/collection/eupl/eupl-text-eupl-12
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::str::FromStr;

use tempfile::TempDir;
use tss_esapi::{Context, Tcti};

#[allow(dead_code)]
pub fn get_tpm2_ctx() -> Context {
    let tcti_path = match std::env::var("TEST_TCTI") {
        Ok(val) => val,
        Err(_) => "tabrmd:".to_string(),
    };

    let tcti = Tcti::from_str(&tcti_path).unwrap();
    Context::new(tcti).unwrap()
}

fn get_signtool_location() -> PathBuf {
    let loc_path = match std::env::var("SIGNTOOL") {
        Ok(val) => val,
        Err(_) => "../clevis-pin-tpm2-signtool/clevis-pin-tpm2-signtool".to_string(),
    };
    let loc_path = Path::new(&loc_path);
    if !loc_path.exists() {
        panic!("Signtool could not be found, please set $SIGNTOOL");
    }
    loc_path.canonicalize().expect("Signtool path is incorrect")
}

#[allow(dead_code)]
pub fn run_with_tempdir<F, R>(f: F) -> R
where
    // We only need to call f once
    F: FnOnce(&Path) -> R,
{
    let tempdir = TempDir::new().unwrap();
    f(tempdir.path())
}

#[allow(dead_code)]
pub fn run_signtool(temp_dir: &Path, input: &str) -> String {
    let signtool_loc = get_signtool_location();
    let mut child = Command::new(signtool_loc)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .current_dir(temp_dir)
        .spawn()
        .expect("Failed to spawn signtool");

    {
        let stdin = child.stdin.as_mut().expect("Failed to open stdin");
        stdin
            .write_all(input.as_bytes())
            .expect("Failed to write stdin");
    }
    let output = child.wait_with_output().expect("Failed to read stdout");
    unsafe { String::from_utf8_unchecked(output.stdout) }
}
