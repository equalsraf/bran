#![recursion_limit="128"]

extern crate webdriver_client;
use webdriver_client::chrome::ChromeDriver;
use webdriver_client::messages::NewSessionCmd;
use webdriver_client::{Driver, JsonValue};

#[macro_use]
extern crate serde_json;
extern crate mktemp;
extern crate base64;
extern crate stderrlog;
extern crate clap;
use clap::{App, AppSettings, Arg, SubCommand, ArgMatches};

extern crate bran;
use bran::{get_session, ExitOnError, get_property, foreach_element, foreach_frame, exec_script};

use std::env;
use std::fs;
use std::io::{self, Read};
use std::str::FromStr;
use std::process;
use std::thread;
use std::time::Duration;

/// Start chromedriver.
///
/// The function blocks waiting for the browser to be finished
///
/// - if -S is passed by the user the function calls the $SHELL and
///   waits for the shell process to finish.
/// - otherwise the function starts the chrome driver and blocks
///   until its session is no longer available.
///
/// When this function ends the session is dropped and the profile
/// temporary folder is removed.
fn cmd_start_chrome(args: &ArgMatches) {
    let tmp = mktemp::Temp::new_dir()
        .unwrap_or_exitmsg(-1, "Unable to create tmp folder");

    let driver = ChromeDriver::build()
        // Dont kill the child driver on exit
        .kill_on_drop(true)
        .spawn()
        .unwrap_or_exitmsg(-1, "Unable to start driver");

    let url = driver.url().to_string();
    let path = tmp.as_ref().to_string_lossy();

    let mut prefs = JsonValue::from_str("{}").unwrap();
    if let Some(path) = args.value_of("PREFS") {
        let mut data = String::new();
        let mut f = fs::File::open(&path)
            .unwrap_or_exitmsg(-1, "Unable to read PREFS file");
        f.read_to_string(&mut data)
            .unwrap_or_exitmsg(-1, "Unable to read PREFS file");
        let val = JsonValue::from_str(&data)
            .unwrap_or_exitmsg(-1, "Unable to read PREFS file");
        prefs = val;
    }

    let mut ext = Vec::new();
    if let Some(iter) = args.values_of("EXTENSION") {
        for path in iter {
            let mut ext_f = fs::File::open(&path)
                .unwrap_or_exitmsg(-1, "Unable to open extension");
            let mut data = Vec::new();
            ext_f.read_to_end(&mut data)
                .unwrap_or_exitmsg(-1, "Unable to read extension file");
            let crx = base64::encode(&data);
            ext.push(crx);
        }
    }

    // setup all the parameters we want, basically a large json blob,
    // see https://sites.google.com/a/chromium.org/chromedriver/capabilities
    let mut params = NewSessionCmd::default();
    params.always_match("goog:chromeOptions", json!({
        "w3c": true, // This must be true for webdriver to work
        // FIXME the user-data-dir seems to play havoc with the use of the GPU, I have not been
        // able to figure it out so its hardcoded here TODO allow the caller to override arguments
        "args": ["--disable-gpu", format!("--user-data-dir={}", path)],
        // look inside you profile in the Preferences file for examples
        "prefs": prefs,
        "extensions": &ext,
    }));

    let session = driver.session(&params)
        .unwrap_or_exitmsg(-1, "Unable to create browser session");

    println!("export BRAN_URL={}", url);
    println!("export BRAN_SESSION={}", session.session_id());
    println!("export BRAN_PROFILE={}", path);

    if args.is_present("spawn-shell") {
        env::set_var("BRAN_URL", &url);
        env::set_var("BRAN_SESSION", session.session_id());
        env::set_var("BRAN_PROFILE", tmp.as_ref());

        let shell = env::var("SHELL")
            .unwrap_or_exitmsg(-1, "Unable to spawn user shell");
        let mut child = process::Command::new(shell)
            .spawn()
            .unwrap_or_exitmsg(-1, "Unable to spawn user shell");
        let _ = child.wait();
        println!("SHELL has finished, dropping browser");
    } else {
        let mut count = 0;
        loop {
            if count > 3 {
                break;
            }

            thread::sleep(Duration::new(15, 0));
            // see https://bugs.chromium.org/p/chromedriver/issues/detail?id=346
            // getting the url might fail, but hopefully this is safe to call
            match session.get_window_handles() {
                Err(_err) => {
                    count += 1;
                }
                Ok(_) => (),
            }
        }
    }
}

fn cmd_windows() -> Result<(), webdriver_client::Error> {
    let mut session = get_session();
    let prev = session.get_window_handle()?;
    for win in session.get_window_handles()? {
        session.switch_window(&win)?;
        let title = session.get_title()?;
        println!("{} \"{}\"", win, title);
    }

    session.switch_window(&prev)?;
    Ok(())
}

/// Common options for handling JSON data, see `print_json_value()`
fn option_json_filters<'a, 'b>() -> [Arg<'a, 'b>; 1] {
    [
        Arg::with_name("FILTER-STR")
            .long("filter-str")
            .help("Print string values, ignore other types"),
    ]
}

fn print_json_value(val: &JsonValue, args: &ArgMatches) {
    if args.is_present("FILTER-STR") {
        if let JsonValue::String(ref val) = *val {
            println!("{}", val);
        }
    } else if JsonValue::Null != *val {
        println!("{}", val);
    }
}

fn main() {
    let matches = App::new("ff")
        .about("browsers from your shell")
        .setting(AppSettings::SubcommandRequiredElseHelp)
        .setting(AppSettings::VersionlessSubcommands)
        .arg(Arg::with_name("verbose")
             .help("Increases verbosity")
             .short("v")
             .multiple(true)
             .long("verbose"))
        .subcommand(SubCommand::with_name("start")
                    .about("Start a new browser instance")
                    .arg(Arg::with_name("spawn-shell")
                         .help("Spawn shell and kill driver on shell exit")
                         .long("spawn-shell")
                         .short("S")
                         .takes_value(false))
                    .arg(Arg::with_name("EXTENSION")
                         .help("Load browser extension from file")
                         .long("extension")
                         .short("X")
                         .takes_value(true)
                         .multiple(true))
                    .arg(Arg::with_name("PREFS")
                         .help("Load json prefs from file")
                         .long("prefs")
                         .short("P")
                         .takes_value(true)))
        .subcommand(SubCommand::with_name("go")
                    .about("Navigate to URL")
                    .arg(Arg::with_name("URL")
                         .required(true)
                        ))
        .subcommand(SubCommand::with_name("back")
                    .about("Go back to the previous page in history"))
        .subcommand(SubCommand::with_name("forward")
                    .about("Go forward to the next page in history"))
        .subcommand(SubCommand::with_name("refresh")
                    .about("Refresh page"))
        .subcommand(SubCommand::with_name("source")
                    .about("Print page source"))
        .subcommand(SubCommand::with_name("exec")
                    .arg(Arg::with_name("all-frames")
                         .short("A"))
                    .arg(Arg::with_name("SCRIPT")
                         .required(true)
                         .help("Javascript code"))
                    .arg(Arg::with_name("ARG")
                         .multiple(true)
                         .required(false)
                         .help("Script arguments[]"))
                    .args(&option_json_filters())
                    .about("Executes script, print its return value"))
        .subcommand(SubCommand::with_name("property")
                    .arg(Arg::with_name("all-frames")
                         .short("A"))
                    .arg(Arg::with_name("SELECTOR")
                         .required(true))
                    .arg(Arg::with_name("NAME")
                         .required(true))
                    .args(&option_json_filters())
                    .about("Print element property")
                    .alias("prop"))
//        .subcommand(SubCommand::with_name("instances")
//                    .about("List running ff instances"))
        .subcommand(SubCommand::with_name("title")
                    .about("Print page title"))
        .subcommand(SubCommand::with_name("url")
                    .about("Print page url"))
//        .subcommand(SubCommand::with_name("quit")
//                    .arg(option_port())
//                    .about("Close the browser"))
        .subcommand(SubCommand::with_name("windows")
                    .about("List browser windows"))
        .subcommand(SubCommand::with_name("switch")
                    .arg(Arg::with_name("WINDOW")
                         .required(true))
                    .about("Switch browser window"))
        .get_matches();

    stderrlog::new()
            .module("webdriver_client")
            .verbosity(matches.occurrences_of("verbose") as usize)
            .init()
            .expect("Unable to initialize stderr output");

    match matches.subcommand() {
        ("back", _) => {
            get_session().back()
                .unwrap_or_exitmsg(-1, "Error calling driver");
        }
        ("exec", Some(ref args)) => {
            let mut session = get_session();
            let mut js = args.value_of("SCRIPT").unwrap().to_owned();
            if js == "-" {
                js.clear();
                io::stdin().read_to_string(&mut js).unwrap_or_exitmsg(-1, "Error reading script from stdin");
            }

            let mut script_args = Vec::new();
            if let Some(l) = args.values_of("ARG") {
                for arg in l {
                    let arg = JsonValue::from_str(arg).unwrap_or_exitmsg(-1, "Script argument is invalid JSON");
                    script_args.push(arg);
                }
            }

            session.switch_to_frame(JsonValue::Null).unwrap_or_exit(-1);

            if args.is_present("all-frames") {
                foreach_frame(&mut session, &|session| {
                    match exec_script(session, &js, script_args.clone()) {
                        Ok(val) => {
                            print_json_value(&val, args);
                            Ok(())
                        }
                        Err(err) => Err(err),
                    }
                }).unwrap_or_exit(-1);
            } else {
                let res =  exec_script(&session, &js, script_args.clone())
                    .unwrap_or_exit(-1);
                print_json_value(&res, args);
            }

            session.switch_to_frame(JsonValue::Null).unwrap_or_exit(-1);
        }
        ("forward", _) => {
            get_session().forward()
                .unwrap_or_exitmsg(-1, "Error calling driver");
        }
        ("go", Some(ref args)) => {
            let url_arg = args.value_of("URL").unwrap();
            let session = get_session();
            session.go(url_arg)
                .unwrap_or_exitmsg(-1, "Error calling driver");
        }
        ("property", Some(ref args)) => {
            let session = get_session();
            let propname = args.value_of("NAME").unwrap();
            session.switch_to_frame(JsonValue::Null).unwrap_or_exit(-1);
            let selector =  args.value_of("SELECTOR").unwrap();

            if args.is_present("all-frames") {
                foreach_frame(&session, &|session| {
                    foreach_element(session, selector, &|elem| {
                        let val = get_property(session, propname, elem)
                            .expect("Error executing script");
                        print_json_value(&val, args);
                        Ok(())
                    })
                }).unwrap_or_exit(-1);
            } else {
                foreach_element(&session, selector, &|elem| {
                    let val = get_property(&session, propname, elem)
                        .expect("Error executing script");
                    print_json_value(&val, args);
                    Ok(())
                }).unwrap_or_exit(-1);
            }

            session.switch_to_frame(JsonValue::Null).unwrap_or_exit(-1);
        }
        ("refresh", _) => {
            get_session().refresh()
                .unwrap_or_exitmsg(-1, "Error calling driver");
        }
        ("start", Some(ref args)) => {
            // The environment variable $BRAN_NOFORK is used to signal the current
            // bran process should block instead of calling a child process.
            if args.is_present("spawn-shell") || env::var_os("BRAN_NOFORK").is_some() {
                cmd_start_chrome(args);
            } else {
                let mut child_args: Vec<_> = env::args().collect();
                process::Command::new(&child_args[0])
                    .args(&child_args[1..])
                    .env("BRAN_NOFORK", "1")
                    .spawn()
                    .unwrap_or_exitmsg(-1, "Unable to spawn child process");
            }
        }
        ("title", _) => {
            let session = get_session();
            let url = session.get_title()
                .unwrap_or_exitmsg(-1, "Error calling driver");
            println!("{}", url);
        }
        ("url", _) => {
            let session = get_session();
            let url = session.get_current_url()
                .unwrap_or_exitmsg(-1, "Error calling driver");
            println!("{}", url);
        },
        ("source", _) => println!("{}", get_session()
                                  .get_page_source()
                                  .unwrap_or_exitmsg(-1, "Error calling driver")),
        ("switch", Some(ref args)) => {
            let mut session = get_session();
            let idx = usize::from_str(args.value_of("WINDOW").unwrap())
                .expect("Invalid WINDOW index");
            let mut handles = session.get_window_handles()
                .unwrap_or_exitmsg(-1, "Unable to get window list");
            let handle = handles.drain(..)
                .nth(idx)
                .unwrap_or_exitmsg(-1, "Index is invalid");
            session.switch_window(&handle)
                .unwrap_or_exitmsg(-1, "Unable to switch window");
        }
        ("windows", _) => cmd_windows().unwrap_or_exit(-1),
        _ => panic!("Unsupported command"),
    }
}
