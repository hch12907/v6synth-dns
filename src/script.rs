use std::collections::HashSet;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::path::Path;
use std::time::Duration;

use async_channel::{self, Receiver, Sender};
use hickory_proto::rr::{RData, RecordType};
use hickory_resolver::TokioAsyncResolver;
use ipnetwork::Ipv4Network;
use rhai::def_package;
use rhai::packages::{ArithmeticPackage, BasicArrayPackage, BasicMapPackage, LogicPackage};
use rhai::plugin::*;
use rhai::{Dynamic, Engine, EvalAltResult, Scope, AST};
use serde::de::IntoDeserializer;
use serde::Deserialize;
use tokio::time::timeout;
use tracing::{error, info, warn};

pub struct LoadedScripts {
    pub scripts: Vec<Script>,
    pub blacklist: HashSet<String>,
}

pub struct Script {
    ast: AST,
    ipv4_ranges: Vec<Ipv4Network>,
    cname_filter: String,
}

impl Script {
    pub fn ast(&self) -> &AST {
        &self.ast
    }

    pub fn ipv4_ranges(&self) -> &[Ipv4Network] {
        &self.ipv4_ranges
    }

    pub fn cname_filter(&self) -> &str {
        &self.cname_filter
    }
}

enum ScriptCommand {
    ResolveA(String),
    ResolveAAAA(String),
    ResolveCNAME(String),
    ResolveCNAMEChain(String),
    ResolveNS(String),
    ResolveSOA(String),
    ResolveTXT(String),
}

enum ScriptReply {
    Resolved(String),
}

struct ScriptResolver {
    // The script is always the first one to send messages, e.g. resolve(...).
    // The host will send back replies to the messages.
    channel_to_script: Sender<ScriptReply>,
    channel_to_host: Receiver<ScriptCommand>,
}

impl ScriptResolver {
    fn register(engine: &mut Engine) -> Self {
        // TH = To Host, TS = To Script
        let (ts_sender, ts_receiver) = async_channel::bounded(1);
        let (th_sender, th_receiver) = async_channel::bounded(1);

        engine.register_fn(
            "resolve",
            move |hostname: String, record: String| -> String {
                let command = match record.as_ref() {
                    "A" => ScriptCommand::ResolveA(hostname),
                    "AAAA" => ScriptCommand::ResolveAAAA(hostname),
                    "CNAME" => ScriptCommand::ResolveCNAME(hostname),
                    "CNAME_CHAIN" => ScriptCommand::ResolveCNAMEChain(hostname),
                    "NS" => ScriptCommand::ResolveNS(hostname),
                    "SOA" => ScriptCommand::ResolveSOA(hostname),
                    "TXT" => ScriptCommand::ResolveTXT(hostname),

                    _ => return String::new(),
                };

                if let Err(_) = th_sender.send_blocking(command) {
                    return String::new();
                }

                let Ok(reply) = ts_receiver.recv_blocking() else {
                    return String::new();
                };

                match reply {
                    ScriptReply::Resolved(res) => res,
                }
            },
        );

        Self {
            channel_to_script: ts_sender,
            channel_to_host: th_receiver,
        }
    }

    async fn execute_alongside_script(self, resolver: TokioAsyncResolver) {
        let result = tokio::task::spawn(async move {
            macro_rules! dns_record {
                ($hostname:expr, $record_type:expr, $rdata:path) => {{
                    let reply = timeout(
                        Duration::from_secs(1),
                        resolver.lookup($hostname, $record_type),
                    )
                    .await
                    .ok();

                    reply
                        .and_then(|result| result.ok())
                        .and_then(|lookup| {
                            lookup
                                .record_iter()
                                .nth(0)
                                .and_then(|rec| match rec.data() {
                                    $rdata(data) => Some(data.to_string()),
                                    _ => None,
                                })
                        })
                        .unwrap_or_default()
                }};
            }

            loop {
                let reply = match self.channel_to_host.recv().await {
                    Ok(ScriptCommand::ResolveA(hostname)) => {
                        dns_record!(hostname, RecordType::A, RData::A)
                    }
                    Ok(ScriptCommand::ResolveAAAA(hostname)) => {
                        dns_record!(hostname, RecordType::AAAA, RData::AAAA)
                    }
                    Ok(ScriptCommand::ResolveCNAME(hostname)) => {
                        dns_record!(hostname, RecordType::CNAME, RData::CNAME)
                    }
                    Ok(ScriptCommand::ResolveCNAMEChain(hostname)) => {
                        let reply = timeout(
                            Duration::from_secs(1),
                            // we can't get a CNAME chain if we queried for CNAME 
                            resolver.lookup(hostname, RecordType::A),
                        )
                        .await
                        .ok();

                        reply
                            .and_then(|result| result.ok())
                            .map(|lookup| {
                                let mut cname = String::new();
                                for record in lookup.record_iter() {
                                    if let RData::CNAME(data) = record.data() {
                                        cname = data.to_string();
                                    }
                                }
                                cname
                            })
                            .unwrap_or_default()
                    }
                    Ok(ScriptCommand::ResolveNS(hostname)) => {
                        dns_record!(hostname, RecordType::NS, RData::NS)
                    }
                    Ok(ScriptCommand::ResolveSOA(hostname)) => {
                        dns_record!(hostname, RecordType::SOA, RData::SOA)
                    }
                    Ok(ScriptCommand::ResolveTXT(hostname)) => {
                        dns_record!(hostname, RecordType::TXT, RData::TXT)
                    }
                    Err(async_channel::RecvError) => break,
                };

                self.channel_to_script
                    .send(ScriptReply::Resolved(reply))
                    .await
                    .unwrap();
            }
        })
        .await;

        if let Err(e) = result {
            if e.is_panic() {
                error!("the script resolver panicked during execution");
            }
        }
    }
}

pub struct ScriptExecution {
    engine: Engine,
    resolver: ScriptResolver,
    ast: AST,
}

impl ScriptExecution {
    pub fn from_ast(ast: &AST) -> Self {
        let mut engine = Engine::new();
        
        // this adds the resolve(hostname, record_type) function to the scripts
        let resolver = ScriptResolver::register(&mut engine);

        Self {
            engine,
            resolver,
            ast: ast.clone(),
        }
    }

    pub async fn execute(
        self,
        hostname: String,
        ipv4: Ipv4Addr,
        size: u32,
        cname: String,
        resolver: TokioAsyncResolver,
    ) -> Option<Ipv6Addr> {
        let args = (hostname, ipv4.to_string(), size as i64, cname);

        let result = tokio::task::spawn_blocking(move || {
            let ast = self.ast;
            let mut scope = Scope::new();
            let result = self
                .engine
                .call_fn::<String>(&mut scope, &ast, "main", args);

            if let Err(ref e) = result {
                warn!("script execution failed with {:?}", e);
            }

            result.ok()
        });

        self.resolver.execute_alongside_script(resolver).await;

        let result = result.await.ok()??;
        result.parse::<Ipv6Addr>().ok()
    }
}

pub fn load_scripts(dir_path: &Path) -> Result<LoadedScripts, Box<EvalAltResult>> {
    let script_dir = dir_path
        .read_dir()
        .expect("unable to open script directory");

    let mut asts = Vec::new();
    let mut blacklist = HashSet::new();

    let engine = Engine::new();

    for entry in script_dir {
        let entry = entry.expect("unable to read directory entry");

        if entry
            .file_type()
            .expect("unable to tell file type")
            .is_file()
        {
            let path = entry.path();

            if path.extension().and_then(|ext| ext.to_str()) == Some("rhai") {
                info!("parsing {:?}", path);

                let ast = engine
                    .compile_file(entry.path())
                    .expect("failed to compile script");

                let mut scope = Scope::new();
                let info = engine
                    .call_fn::<Dynamic>(&mut scope, &ast, "init", ())
                    .expect("a script failed to initialize");

                #[derive(serde_derive::Deserialize, Debug)]
                struct InitInfo {
                    priority: Option<i64>,
                    ipv4_ranges: Vec<Ipv4Network>,
                    cname_filter: Option<String>,
                    blacklisted_names: Option<Vec<String>>,
                }

                if let Ok(val) = InitInfo::deserialize(info.into_deserializer()) {
                    let priority = val.priority.unwrap_or(0);
                    let script = Script {
                        ast,
                        ipv4_ranges: val.ipv4_ranges,
                        cname_filter: val.cname_filter.unwrap_or_default(),
                    };

                    asts.push((priority, script));

                    if let Some(names) = val.blacklisted_names {
                        blacklist.extend(names.iter().cloned());
                    }
                } else {
                    panic!("the init() of a script returned unexpected value");
                }
            }
        }
    }

    asts.sort_by_key(|(priority, _)| -priority);

    let loaded = LoadedScripts {
        scripts: asts.into_iter().map(|(_, script)| script).collect(),
        blacklist,
    };

    Ok(loaded)
}

// Define plugin module.
#[export_module]
mod v6synth_plugin_module {
    pub const MY_NUMBER: i64 = 42;

    pub fn greet(name: &str) -> String {
        format!("hello, {}!", name)
    }
}

def_package! {
    pub ScriptPackage(module) : ArithmeticPackage, LogicPackage, BasicArrayPackage, BasicMapPackage
    {
        combine_with_exported_module!(module, "v6synth", v6synth_plugin_module);
    } |> |_engine| {
        // nothing
    }
}
