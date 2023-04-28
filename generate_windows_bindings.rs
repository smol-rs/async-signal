#!/usr/bin/env rust-script

//! Easy script for generating the bindings that we need to Windows.
//! 
//! ```cargo
//! [dependencies]
//! windows-bindgen = "0.49"
//! ```

use std::env;

fn main() {
    let apis = &[
        "Windows.Win32.System.Console.SetConsoleCtrlHandler",
        "Windows.Win32.System.Console.PHANDLER_ROUTINE",
        "Windows.Win32.System.Console.CTRL_C_EVENT",
        "Windows.Win32.Foundation::BOOL"
    ];

    println!("{}", windows_bindgen::standalone(apis));
}
