use rand::{thread_rng, Rng};
use secrecy::Zeroize;
use std::io::{self, BufRead, BufReader, Read, Write};
use std::iter;
use std::path::Path;
use std::process::{ChildStdin, ChildStdout, Command, Stdio};

use crate::format::{grease_the_joint, read, write, Stanza};

pub const IDENTITY_V1: &str = "identity-v1";
pub const RECIPIENT_V1: &str = "recipient-v1";

const COMMAND_DONE: &str = "done";
const RESPONSE_OK: &str = "ok";
const RESPONSE_FAIL: &str = "fail";
const RESPONSE_UNSUPPORTED: &str = "unsupported";

/// Result type for the plugin protocol.
///
/// - The outer error indicates a problem with the IPC transport or state machine; these
///   should result in the state machine being terminated and the connection closed.
/// - The inner error indicates an error within the plugin protocol, that the recipient
///   should explicitly handle.
pub type Result<T, E> = io::Result<std::result::Result<T, E>>;

type UnidirResult<A, B, C, E> = io::Result<(
    std::result::Result<Vec<A>, Vec<E>>,
    std::result::Result<Vec<B>, Vec<E>>,
    Option<std::result::Result<Vec<C>, Vec<E>>>,
)>;

/// A connection to a plugin binary.
pub struct Connection<R: Read, W: Write> {
    input: BufReader<R>,
    output: W,
    buffer: String,
    _working_dir: Option<tempfile::TempDir>,
}

impl Connection<ChildStdout, ChildStdin> {
    /// Start a plugin binary with the given state machine.
    pub fn open(binary: &Path, state_machine: &str) -> io::Result<Self> {
        let working_dir = tempfile::tempdir()?;
        let process = Command::new(binary.canonicalize()?)
            .arg(format!("--age-plugin={}", state_machine))
            .current_dir(working_dir.path())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;
        let input = BufReader::new(process.stdout.expect("could open stdout"));
        let output = process.stdin.expect("could open stdin");
        Ok(Connection {
            input,
            output,
            buffer: String::new(),
            _working_dir: Some(working_dir),
        })
    }
}

impl Connection<io::Stdin, io::Stdout> {
    /// Initialise a connection from an age client.
    pub fn accept() -> Self {
        Connection {
            input: BufReader::new(io::stdin()),
            output: io::stdout(),
            buffer: String::new(),
            _working_dir: None,
        }
    }
}

impl<R: Read, W: Write> Connection<R, W> {
    fn send<S: AsRef<str>>(
        &mut self,
        command: &str,
        metadata: &[S],
        data: &[u8],
    ) -> io::Result<()> {
        use cookie_factory::GenError;

        cookie_factory::gen_simple(write::age_stanza(command, metadata, data), &mut self.output)
            .map_err(|e| match e {
                GenError::IoError(e) => e,
                e => io::Error::new(io::ErrorKind::Other, format!("{}", e)),
            })
            .and_then(|w| w.flush())
    }

    fn send_stanza<S: AsRef<str>>(
        &mut self,
        command: &str,
        metadata: &[S],
        stanza: &Stanza,
    ) -> io::Result<()> {
        let metadata: Vec<_> = metadata
            .iter()
            .map(|s| s.as_ref())
            .chain(iter::once(stanza.tag.as_str()))
            .chain(stanza.args.iter().map(|s| s.as_str()))
            .collect();

        self.send(command, &metadata, &stanza.body)
    }

    fn receive(&mut self) -> io::Result<Stanza> {
        let (stanza, consumed) = loop {
            match read::age_stanza(self.buffer.as_bytes()) {
                Ok((remainder, r)) => break (r.into(), self.buffer.len() - remainder.len()),
                Err(nom::Err::Incomplete(_)) => {
                    if self.input.read_line(&mut self.buffer)? == 0 {
                        return Err(io::Error::new(
                            io::ErrorKind::UnexpectedEof,
                            "incomplete response",
                        ));
                    };
                }
                Err(_) => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "invalid response",
                    ));
                }
            }
        };

        // We are finished with any prior response.
        let remainder = self.buffer.split_off(consumed);
        self.buffer.zeroize();
        self.buffer = remainder;

        Ok(stanza)
    }

    fn grease_gun(&mut self) -> impl Iterator<Item = Stanza> {
        // Add 5% grease
        let mut rng = thread_rng();
        (0..2)
            .map(move |_| {
                if rng.gen_range(0, 100) < 5 {
                    Some(grease_the_joint())
                } else {
                    None
                }
            })
            .flatten()
    }

    fn done(&mut self) -> io::Result<()> {
        self.send::<&str>(COMMAND_DONE, &[], &[])
    }

    /// Runs a unidirectional phase as the controller.
    pub fn unidir_send<P: FnOnce(UnidirSend<R, W>) -> io::Result<()>>(
        &mut self,
        phase_steps: P,
    ) -> io::Result<()> {
        phase_steps(UnidirSend(self))?;
        for grease in self.grease_gun() {
            self.send(&grease.tag, &grease.args, &grease.body)?;
        }
        self.done()
    }

    /// Runs a unidirectional phase as the recipient.
    ///
    /// # Arguments
    ///
    /// `command_a`, `command_b`, and (optionally) `command_c` are the known commands that
    /// are expected to be received. All other received commands (including grease) will
    /// be ignored.
    pub fn unidir_receive<A, B, C, E, F, G, H>(
        &mut self,
        command_a: (&str, F),
        command_b: (&str, G),
        command_c: (Option<&str>, H),
    ) -> UnidirResult<A, B, C, E>
    where
        F: Fn(Stanza) -> std::result::Result<A, E>,
        G: Fn(Stanza) -> std::result::Result<B, E>,
        H: Fn(Stanza) -> std::result::Result<C, E>,
    {
        let mut res_a = Ok(vec![]);
        let mut res_b = Ok(vec![]);
        let mut res_c = Ok(vec![]);

        for stanza in iter::repeat_with(|| self.receive()).take_while(|res| match res {
            Ok(stanza) => stanza.tag != COMMAND_DONE,
            _ => true,
        }) {
            let stanza = stanza?;

            fn validate<T, E>(
                val: std::result::Result<T, E>,
                res: &mut std::result::Result<Vec<T>, Vec<E>>,
            ) {
                // Structurally validate the stanza against this command.
                match val {
                    Ok(a) => {
                        if let Ok(stanzas) = res {
                            stanzas.push(a)
                        }
                    }
                    Err(e) => match res {
                        Ok(_) => *res = Err(vec![e]),
                        Err(errors) => errors.push(e),
                    },
                }
            }

            if stanza.tag.as_str() == command_a.0 {
                validate(command_a.1(stanza), &mut res_a)
            } else if stanza.tag.as_str() == command_b.0 {
                validate(command_b.1(stanza), &mut res_b)
            } else if let Some(tag) = command_c.0 {
                if stanza.tag.as_str() == tag {
                    validate(command_c.1(stanza), &mut res_c)
                }
            }
        }

        Ok((res_a, res_b, command_c.0.map(|_| res_c)))
    }

    /// Runs a bidirectional phase as the controller.
    pub fn bidir_send<P: FnOnce(BidirSend<R, W>) -> io::Result<()>>(
        &mut self,
        phase_steps: P,
    ) -> io::Result<()> {
        phase_steps(BidirSend(self))?;
        for grease in self.grease_gun() {
            self.send(&grease.tag, &grease.args, &grease.body)?;
            self.receive()?;
        }
        self.done()
    }

    /// Runs a bidirectional phase as the recipient.
    pub fn bidir_receive<H>(&mut self, commands: &[&str], mut handler: H) -> io::Result<()>
    where
        H: FnMut(Stanza, Reply<R, W>) -> Response,
    {
        loop {
            let stanza = self.receive()?;
            match stanza.tag.as_str() {
                COMMAND_DONE => break Ok(()),
                t if commands.contains(&t) => handler(stanza, Reply(self)).0?,
                _ => self.send::<&str>(RESPONSE_UNSUPPORTED, &[], &[])?,
            }
        }
    }
}

/// Actions that a controller may take during a unidirectional phase.
///
/// Grease is applied automatically.
pub struct UnidirSend<'a, R: Read, W: Write>(&'a mut Connection<R, W>);

impl<'a, R: Read, W: Write> UnidirSend<'a, R, W> {
    /// Send a command.
    pub fn send(&mut self, command: &str, metadata: &[&str], data: &[u8]) -> io::Result<()> {
        for grease in self.0.grease_gun() {
            self.0.send(&grease.tag, &grease.args, &grease.body)?;
        }
        self.0.send(command, metadata, data)
    }

    /// Send an entire stanza.
    pub fn send_stanza(
        &mut self,
        command: &str,
        metadata: &[&str],
        stanza: &Stanza,
    ) -> io::Result<()> {
        for grease in self.0.grease_gun() {
            self.0.send(&grease.tag, &grease.args, &grease.body)?;
        }
        self.0.send_stanza(command, metadata, stanza)
    }
}

/// Actions that a controller may take during a bidirectional phase.
///
/// Grease is applied automatically.
pub struct BidirSend<'a, R: Read, W: Write>(&'a mut Connection<R, W>);

impl<'a, R: Read, W: Write> BidirSend<'a, R, W> {
    /// Send a command and receive a response.
    pub fn send(&mut self, command: &str, metadata: &[&str], data: &[u8]) -> Result<Stanza, ()> {
        for grease in self.0.grease_gun() {
            self.0.send(&grease.tag, &grease.args, &grease.body)?;
            self.0.receive()?;
        }
        self.0.send(command, metadata, data)?;
        let s = self.0.receive()?;
        match s.tag.as_ref() {
            RESPONSE_OK => Ok(Ok(s)),
            RESPONSE_FAIL => Ok(Err(())),
            tag => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("unexpected response: {}", tag),
            )),
        }
    }

    /// Send an entire stanza.
    pub fn send_stanza(
        &mut self,
        command: &str,
        metadata: &[&str],
        stanza: &Stanza,
    ) -> Result<Stanza, ()> {
        for grease in self.0.grease_gun() {
            self.0.send(&grease.tag, &grease.args, &grease.body)?;
            self.0.receive()?;
        }
        self.0.send_stanza(command, metadata, stanza)?;
        let s = self.0.receive()?;
        match s.tag.as_ref() {
            RESPONSE_OK => Ok(Ok(s)),
            RESPONSE_FAIL => Ok(Err(())),
            tag => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("unexpected response: {}", tag),
            )),
        }
    }
}

/// The possible replies to a bidirectional command.
pub struct Reply<'a, R: Read, W: Write>(&'a mut Connection<R, W>);

impl<'a, R: Read, W: Write> Reply<'a, R, W> {
    /// Reply with `ok` and optional data.
    pub fn ok(self, data: Option<&[u8]>) -> Response {
        Response(
            self.0
                .send::<&str>(RESPONSE_OK, &[], data.unwrap_or_default()),
        )
    }

    /// The command failed (for example, the user failed to respond to an input request).
    pub fn fail(self) -> Response {
        Response(self.0.send::<&str>(RESPONSE_FAIL, &[], &[]))
    }
}

/// A response to a bidirectional command.
pub struct Response(io::Result<()>);

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use super::*;

    pub struct Pipe(Vec<u8>);

    impl Pipe {
        pub fn new() -> Arc<Mutex<Self>> {
            Arc::new(Mutex::new(Pipe(Vec::new())))
        }
    }

    pub struct PipeReader {
        pipe: Arc<Mutex<Pipe>>,
    }

    impl PipeReader {
        pub fn new(pipe: Arc<Mutex<Pipe>>) -> Self {
            PipeReader { pipe }
        }
    }

    impl Read for PipeReader {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            let mut pipe = self.pipe.lock().unwrap();
            let n_in = pipe.0.len();
            let n_out = buf.len();
            if n_in == 0 {
                Err(io::Error::new(io::ErrorKind::WouldBlock, ""))
            } else if n_out < n_in {
                buf.copy_from_slice(&pipe.0[..n_out]);
                pipe.0 = pipe.0.split_off(n_out);
                Ok(n_out)
            } else {
                (&mut buf[..n_in]).copy_from_slice(&pipe.0);
                pipe.0.clear();
                Ok(n_in)
            }
        }
    }

    pub struct PipeWriter {
        pipe: Arc<Mutex<Pipe>>,
    }

    impl PipeWriter {
        pub fn new(pipe: Arc<Mutex<Pipe>>) -> Self {
            PipeWriter { pipe }
        }
    }

    impl Write for PipeWriter {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            let mut pipe = self.pipe.lock().unwrap();
            pipe.0.extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn mock_plugin() {
        let client_to_plugin = Pipe::new();
        let plugin_to_client = Pipe::new();

        let mut client_conn = Connection {
            input: BufReader::new(PipeReader::new(plugin_to_client.clone())),
            output: PipeWriter::new(client_to_plugin.clone()),
            buffer: String::new(),
            _working_dir: None,
        };
        let mut plugin_conn = Connection {
            input: BufReader::new(PipeReader::new(client_to_plugin)),
            output: PipeWriter::new(plugin_to_client),
            buffer: String::new(),
            _working_dir: None,
        };

        client_conn
            .unidir_send(|mut phase| phase.send("test", &["foo"], b"bar"))
            .unwrap();
        let stanza = plugin_conn
            .unidir_receive::<_, (), (), _, _, _, _>(
                ("test", |s| Ok(s)),
                ("other", |_| Err(())),
                (None, |_| Ok(())),
            )
            .unwrap();
        assert_eq!(
            stanza,
            (
                Ok(vec![Stanza {
                    tag: "test".to_owned(),
                    args: vec!["foo".to_owned()],
                    body: b"bar"[..].to_owned()
                }]),
                Ok(vec![]),
                None
            )
        );
    }
}
