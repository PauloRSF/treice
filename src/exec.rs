use std::{env, path::PathBuf};

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
