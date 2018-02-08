#![recursion_limit="128"]

extern crate webdriver_client;
use webdriver_client::chrome::ChromeDriver;
use webdriver_client::messages::{NewSessionCmd, LocationStrategy, ExecuteCmd};
use webdriver_client::{Driver, JsonValue, DriverSession, Element};

#[macro_use]
extern crate serde_json;
extern crate mktemp;
extern crate base64;
extern crate stderrlog;
extern crate clap;
use clap::{App, AppSettings, Arg, SubCommand, ArgMatches};

use std::fmt::Debug;
use std::env;
use std::fs;
use std::io::{self, Read, Write};
use std::process::exit;
use std::str::FromStr;
use std::process;

trait ExitOnError<T>: Sized {
    fn exit(code: i32, msg: Option<&str>) -> ! {
        if let Some(msg) = msg {
            let _ = writeln!(&mut std::io::stderr(), "{}", msg);
        }
        exit(code);
    }

    fn unwrap_or_exit(self, code: i32) -> T;
    fn unwrap_or_exitmsg(self, code: i32, msg: &str) -> T;
}

impl<T, E: Debug> ExitOnError<T> for std::result::Result<T, E> {
    fn unwrap_or_exit(self, code: i32) -> T {
        match self {
            Ok(res) => res,
            Err(err) => {
                Self::exit(code, Some(&format!("{:?}", err)));
            }
        }
    }

    fn unwrap_or_exitmsg(self, code: i32, msg: &str) -> T {
        match self {
            Ok(res) => res,
            Err(err) => {
                Self::exit(code, Some(&format!("{}: {:?}", msg, err)));
            }
        }
    }
}
impl<T> ExitOnError<T> for Option<T> {
    fn unwrap_or_exit(self, code: i32) -> T {
        match self {
            Some(res) => res,
            None => Self::exit(code, None),
        }
    }
    fn unwrap_or_exitmsg(self, code: i32, msg: &str) -> T {
        match self {
            Some(res) => res,
            None => Self::exit(code, Some(msg)),
        }
    }
}

fn get_session() -> DriverSession{
    let url = env::var("BRAN_URL")
        .unwrap_or_exitmsg(-1, "$BRAN_URL is not set");
    let session_id = env::var("BRAN_SESSION")
        .unwrap_or_exitmsg(-1, "$BRAN_SESSION is not set");
    let mut session = DriverSession::attach(&url, &session_id)
        .unwrap_or_exitmsg(-1, "Unable to attach to session");
    session.drop_session(false);
    session
}

fn cmd_start_chrome(args: &ArgMatches) {
    let mut tmp = mktemp::Temp::new_dir()
        .unwrap_or_exitmsg(-1, "Unable to create tmp folder");

    let spawn_shell = args.is_present("spawn-shell");
    if !spawn_shell {
        tmp.release();
    }

    let driver = ChromeDriver::build()
        // Dont kill the child driver on exit
        .kill_on_drop(spawn_shell)
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

    let mut session = driver.session(&params)
        .unwrap_or_exitmsg(-1, "Unable to create browser session");
    // FIXME: chromedriver session drop seems to hang
    session.drop_session(spawn_shell);

    println!("export BRAN_URL={}", url);
    println!("export BRAN_SESSION={}", session.session_id());
    println!("export BRAN_PROFILE={}", path);

    if spawn_shell {
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

const FRAME_SELECTOR: &'static str = "iframe, frame";

/// Iterate over all frames under the current frame
fn foreach_frame<F>(session: &DriverSession, args: &ArgMatches, f: &F) -> Result<(), webdriver_client::Error>
        where F: Fn(&DriverSession, &ArgMatches) -> Result<(), webdriver_client::Error> {
    f(session, args)?;
    let elements = session.find_elements(FRAME_SELECTOR, LocationStrategy::Css)?;
    for frame in &elements {
        session.switch_to_frame(frame.reference()?)?;
        foreach_frame(session, args, f)?;
        session.switch_to_parent_frame()?;
    }
    Ok(())
}

/// Iterate over elements based on argument "SELECTOR"
fn foreach_element<F, T>(session: &DriverSession, args: &ArgMatches, f: &F) -> Result<(), webdriver_client::Error>
        where F: Fn(&Element) -> Result<T, webdriver_client::Error> {
    let selector =  args.value_of("SELECTOR").unwrap();
    for elem in session.find_elements(selector, LocationStrategy::Css)? {
        f(&elem)?;
    }
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
                    .arg(Arg::with_name("SCRIPT")
                         .required(true)
                         .help("Javascript code"))
                    .arg(Arg::with_name("ARG")
                         .multiple(true)
                         .required(false)
                         .help("Script arguments[]"))
                    .args(&option_json_filters())
                    .about("Executes script in all frames, print its return value"))
        .subcommand(SubCommand::with_name("property")
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
            foreach_frame(&mut session, args, &|session, args| {
                // FIXME add support for async scripts
                let res = session.execute(ExecuteCmd {
                    script: js.clone(),
                    args: script_args.clone(),
                });

                match res {
                    Ok(val) => print_json_value(&val, args),
                    Err(err) => return Err(err),
                }
                Ok(())
            }).unwrap_or_exit(-1);
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
            foreach_frame(&session, args, &|session, args| {
                foreach_element(session, args, &|elem| {
                    // chrome does not implement property, so we emulate it
                    // using js
                    let val = session.execute(ExecuteCmd {
                        script: format!("return arguments[0].{};", propname),
                        // the browser will convert the json reference to a js reference
                        args: vec![elem.reference().unwrap()],
                    }).expect("Error executing script");

                    print_json_value(&val, args);
                    Ok(())
                })
            }).unwrap_or_exit(-1);
            session.switch_to_frame(JsonValue::Null).unwrap_or_exit(-1);
        }
        ("refresh", _) => {
            get_session().refresh()
                .unwrap_or_exitmsg(-1, "Error calling driver");
        }
        ("start", Some(ref args)) => cmd_start_chrome(args),
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
