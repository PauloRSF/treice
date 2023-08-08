use std::{env, path::PathBuf};

use crate::error::TreiceError;

fn find_executable_in_os_lookup_paths(executable_path: &PathBuf) -> Option<PathBuf> {
    match env::var("PATH") {
        Err(_) => None,
        Ok(path_var) => path_var
            .split(':')
            .map(|path| {
                let mut lookup_path = PathBuf::from(path);
                lookup_path.push(executable_path);
                lookup_path
            })
            .find(|lookup_path| lookup_path.exists()),
    }
}

pub fn find_absolute_executable_path(executable_path: &String) -> Option<PathBuf> {
    let executable_path_buf = PathBuf::from(executable_path);

    if executable_path_buf.is_absolute() && executable_path_buf.exists() {
        Some(executable_path_buf)
    } else {
        find_executable_in_os_lookup_paths(&executable_path_buf)
    }
}

pub fn get_executable_path_from_args() -> Result<PathBuf, TreiceError> {
    let path_arg = env::args()
        .nth(1)
        .ok_or(TreiceError::NoExecutableProvided)?;

    find_absolute_executable_path(&path_arg).ok_or(TreiceError::ExecutableNotFound)
}
