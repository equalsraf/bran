
use std::fmt::Debug;
use std::env;
use std::io::Write;
use std::process::exit;

extern crate webdriver_client;
use webdriver_client::messages::{LocationStrategy, ExecuteCmd};
use webdriver_client::{JsonValue, DriverSession, Element};

pub fn get_session() -> DriverSession{
    let url = env::var("BRAN_URL")
        .unwrap_or_exitmsg(-1, "$BRAN_URL is not set");
    let session_id = env::var("BRAN_SESSION")
        .unwrap_or_exitmsg(-1, "$BRAN_SESSION is not set");
    let mut session = DriverSession::attach(&url, &session_id)
        .unwrap_or_exitmsg(-1, "Unable to attach to session");
    session.drop_session(false);
    session
}

pub trait ExitOnError<T>: Sized {
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

/// chrome does not implement property, so we emulate it using js
pub fn get_property(session: &DriverSession, propname: &str, elem: &Element) -> Result<JsonValue, webdriver_client::Error> {
    session.execute(ExecuteCmd {
        script: format!("return arguments[0].{};", propname),
        // the browser will convert the json reference to a js reference
        args: vec![elem.reference().unwrap()],
    })
}

/// Iterate over elements based on argument selector
pub fn foreach_element<F, T>(session: &DriverSession, selector: &str, f: &F) -> Result<(), webdriver_client::Error>
        where F: Fn(&Element) -> Result<T, webdriver_client::Error> {
    for elem in session.find_elements(selector, LocationStrategy::Css)? {
        f(&elem)?;
    }
    Ok(())
}

const FRAME_SELECTOR: &'static str = "iframe, frame";

/// Iterate over all frames under the current frame
pub fn foreach_frame<F>(session: &DriverSession, f: &F) -> Result<(), webdriver_client::Error>
        where F: Fn(&DriverSession) -> Result<(), webdriver_client::Error> {
    f(session)?;
    let elements = session.find_elements(FRAME_SELECTOR, LocationStrategy::Css)?;
    for frame in &elements {
        session.switch_to_frame(frame.reference()?)?;
        foreach_frame(session, f)?;
        session.switch_to_parent_frame()?;
    }
    Ok(())
}

pub fn exec_script(session: &DriverSession, script: &str, arguments: Vec<JsonValue>) -> Result<JsonValue, webdriver_client::Error> {
    session.execute(ExecuteCmd {
        script: script.to_owned(),
        args: arguments,
    })
}
