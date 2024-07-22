#[macro_use]
extern crate serde;
use candid::{Decode, Encode};
use ic_cdk::api::time;
use ic_stable_structures::memory_manager::{MemoryId, MemoryManager, VirtualMemory};
use ic_stable_structures::{BoundedStorable, Cell, DefaultMemoryImpl, StableBTreeMap, Storable};
use regex::Regex;
use std::{borrow::Cow, cell::RefCell};

type Memory = VirtualMemory<DefaultMemoryImpl>;
type IdCell = Cell<u64, Memory>;

#[derive(candid::CandidType, Clone, Serialize, Deserialize, Default)]
struct User {
    id: u64,
    username: String,
    email: String,
    created_at: u64,
}

#[derive(candid::CandidType, Clone, Serialize, Deserialize, Default)]
struct File {
    id: u64,
    owner_id: u64,
    filename: String,
    content: Vec<u8>,
    encrypted: bool,
    created_at: u64,
}

#[derive(candid::CandidType, Clone, Serialize, Deserialize, Default)]
struct AccessControl {
    file_id: u64,
    user_id: u64,
    read: bool,
    write: bool,
    created_at: u64,
}

impl Storable for User {
    fn to_bytes(&self) -> Cow<[u8]> {
        Cow::Owned(Encode!(self).unwrap())
    }

    fn from_bytes(bytes: Cow<[u8]>) -> Self {
        Decode!(bytes.as_ref(), Self).unwrap()
    }
}

impl BoundedStorable for User {
    const MAX_SIZE: u32 = 1024;
    const IS_FIXED_SIZE: bool = false;
}

impl Storable for File {
    fn to_bytes(&self) -> Cow<[u8]> {
        Cow::Owned(Encode!(self).unwrap())
    }

    fn from_bytes(bytes: Cow<[u8]>) -> Self {
        Decode!(bytes.as_ref(), Self).unwrap()
    }
}

impl BoundedStorable for File {
    const MAX_SIZE: u32 = 1024;
    const IS_FIXED_SIZE: bool = false;
}

impl Storable for AccessControl {
    fn to_bytes(&self) -> Cow<[u8]> {
        Cow::Owned(Encode!(self).unwrap())
    }

    fn from_bytes(bytes: Cow<[u8]>) -> Self {
        Decode!(bytes.as_ref(), Self).unwrap()
    }
}

impl BoundedStorable for AccessControl {
    const MAX_SIZE: u32 = 1024;
    const IS_FIXED_SIZE: bool = false;
}

thread_local! {
    static MEMORY_MANAGER: RefCell<MemoryManager<DefaultMemoryImpl>> = RefCell::new(
        MemoryManager::init(DefaultMemoryImpl::default())
    );

    static ID_COUNTER: RefCell<IdCell> = RefCell::new(
        IdCell::init(MEMORY_MANAGER.with(|m| m.borrow().get(MemoryId::new(0))), 0)
            .expect("Cannot create a counter")
    );

    static USER_STORAGE: RefCell<StableBTreeMap<u64, User, Memory>> =
        RefCell::new(StableBTreeMap::init(
            MEMORY_MANAGER.with(|m| m.borrow().get(MemoryId::new(1)))
    ));

    static FILE_STORAGE: RefCell<StableBTreeMap<u64, File, Memory>> =
        RefCell::new(StableBTreeMap::init(
            MEMORY_MANAGER.with(|m| m.borrow().get(MemoryId::new(2)))
    ));

    static ACCESS_CONTROL_STORAGE: RefCell<StableBTreeMap<u64, AccessControl, Memory>> =
        RefCell::new(StableBTreeMap::init(
            MEMORY_MANAGER.with(|m| m.borrow().get(MemoryId::new(3)))
    ));
}

#[derive(candid::CandidType, Deserialize, Serialize)]
struct UserPayload {
    username: String,
    email: String,
}

#[derive(candid::CandidType, Deserialize, Serialize)]
struct FilePayload {
    owner_id: u64,
    filename: String,
    content: Vec<u8>,
    encrypted: bool,
}

#[derive(candid::CandidType, Deserialize, Serialize)]
struct AccessControlPayload {
    file_id: u64,
    user_id: u64,
    read: bool,
    write: bool,
}

#[derive(candid::CandidType, Deserialize, Serialize)]
enum Message {
    Success(String),
    Error(String),
    NotFound(String),
    InvalidPayload(String),
    Unauthorized(String),
}

#[ic_cdk::update]
fn create_user(payload: UserPayload) -> Result<User, Message> {
    if payload.username.is_empty() || payload.email.is_empty() {
        return Err(Message::InvalidPayload(
            "Ensure 'username' and 'email' are provided.".to_string(),
        ));
    }

    let email_regex = Regex::new(r"^[^\s@]+@[^\s@]+\.[^\s@]+$").unwrap();
    if !email_regex.is_match(&payload.email) {
        return Err(Message::InvalidPayload(
            "Invalid email address format".to_string(),
        ));
    }

    let id = ID_COUNTER
        .with(|counter| {
            let current_value = *counter.borrow().get();
            counter.borrow_mut().set(current_value + 1)
        })
        .expect("Cannot increment ID counter");

    let user = User {
        id,
        username: payload.username,
        email: payload.email,
        created_at: current_time(),
    };
    USER_STORAGE.with(|storage| storage.borrow_mut().insert(id, user.clone()));
    Ok(user)
}

#[ic_cdk::update]
fn upload_file(payload: FilePayload) -> Result<File, Message> {
    if payload.filename.is_empty() || payload.content.is_empty() {
        return Err(Message::InvalidPayload(
            "Ensure 'filename' and 'content' are provided.".to_string(),
        ));
    }

    let owner_exists = USER_STORAGE.with(|storage| {
        storage
            .borrow()
            .iter()
            .any(|(_, user)| user.id == payload.owner_id)
    });

    if !owner_exists {
        return Err(Message::NotFound("Owner not found".to_string()));
    }

    let id = ID_COUNTER
        .with(|counter| {
            let current_value = *counter.borrow().get();
            counter.borrow_mut().set(current_value + 1)
        })
        .expect("Cannot increment ID counter");

    let file = File {
        id,
        owner_id: payload.owner_id,
        filename: payload.filename,
        content: payload.content,
        encrypted: payload.encrypted,
        created_at: current_time(),
    };
    FILE_STORAGE.with(|storage| storage.borrow_mut().insert(id, file.clone()));
    Ok(file)
}

#[ic_cdk::update]
fn set_access_control(payload: AccessControlPayload) -> Result<AccessControl, Message> {
    let file_exists = FILE_STORAGE.with(|storage| {
        storage
            .borrow()
            .iter()
            .any(|(_, file)| file.id == payload.file_id)
    });

    if !file_exists {
        return Err(Message::NotFound("File not found".to_string()));
    }

    let user_exists = USER_STORAGE.with(|storage| {
        storage
            .borrow()
            .iter()
            .any(|(_, user)| user.id == payload.user_id)
    });

    if !user_exists {
        return Err(Message::NotFound("User not found".to_string()));
    }

    let id = ID_COUNTER
        .with(|counter| {
            let current_value = *counter.borrow().get();
            counter.borrow_mut().set(current_value + 1)
        })
        .expect("Cannot increment ID counter");

    let access_control = AccessControl {
        file_id: payload.file_id,
        user_id: payload.user_id,
        read: payload.read,
        write: payload.write,
        created_at: current_time(),
    };
    ACCESS_CONTROL_STORAGE.with(|storage| storage.borrow_mut().insert(id, access_control.clone()));
    Ok(access_control)
}

#[ic_cdk::query]
fn get_files_by_user(user_id: u64) -> Result<Vec<File>, Message> {
    FILE_STORAGE.with(|storage| {
        let files: Vec<File> = storage
            .borrow()
            .iter()
            .filter(|(_, file)| file.owner_id == user_id)
            .map(|(_, file)| file.clone())
            .collect();

        if files.is_empty() {
            Err(Message::NotFound("No files found for the user".to_string()))
        } else {
            Ok(files)
        }
    })
}

#[ic_cdk::query]
fn get_access_controls(file_id: u64) -> Result<Vec<AccessControl>, Message> {
    ACCESS_CONTROL_STORAGE.with(|storage| {
        let controls: Vec<AccessControl> = storage
            .borrow()
            .iter()
            .filter(|(_, control)| control.file_id == file_id)
            .map(|(_, control)| control.clone())
            .collect();

        if controls.is_empty() {
            Err(Message::NotFound("No access controls found for the file".to_string()))
        } else {
            Ok(controls)
        }
    })
}

fn current_time() -> u64 {
    time()
}

#[derive(candid::CandidType, Deserialize, Serialize)]
enum Error {
    NotFound { msg: String },
    Unauthorized { msg: String },
}

ic_cdk::export_candid!();
