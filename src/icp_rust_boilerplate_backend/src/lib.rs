#[macro_use]
extern crate serde;
use candid::{Decode, Encode};
use ic_cdk::api::time;
use ic_stable_structures::memory_manager::{MemoryId, MemoryManager, VirtualMemory};
use ic_stable_structures::{BoundedStorable, Cell, DefaultMemoryImpl, StableBTreeMap, Storable};
use std::{borrow::Cow, cell::RefCell};

type Memory = VirtualMemory<DefaultMemoryImpl>;
type IdCell = Cell<u64, Memory>;

#[derive(candid::CandidType, Clone, Serialize, Deserialize, Default)]
struct Alumni {
    id: u64,
    name: String,
    email: String,
    graduation_year: u32,
    created_at: u64,
}

#[derive(candid::CandidType, Clone, Serialize, Deserialize, Default)]
struct Association {
    id: u64,
    name: String,
    description: String,
    alumnis: Vec<u64>, // Field to store alumnis who are members of the association
    created_at: u64,
}

#[derive(candid::CandidType, Clone, Serialize, Deserialize, Default)]
struct Event {
    id: u64,
    association_id: u64,
    title: String,
    description: String,
    date_time: u64,
    location: String,
    organizer: String,
    capacity: u32,
    attendees: Vec<String>,
    created_at: u64,
}

#[derive(candid::CandidType, Clone, Serialize, Deserialize, Default)]
struct MessageToAssociation {
    id: u64,
    association_id: u64,
    sender_id: u64,
    content: String,
    created_at: u64,
}

#[derive(candid::CandidType, Clone, Serialize, Deserialize, Default)]
struct MentorshipRequest {
    id: u64,
    requester_id: u64,
    mentor_id: u64,
    status: String, // e.g., "pending", "approved", "rejected"
    created_at: u64,
}

impl Storable for Alumni {
    fn to_bytes(&self) -> Cow<[u8]> {
        Cow::Owned(Encode!(self).unwrap())
    }

    fn from_bytes(bytes: Cow<[u8]>) -> Self {
        Decode!(bytes.as_ref(), Self).unwrap()
    }
}

impl BoundedStorable for Alumni {
    const MAX_SIZE: u32 = 1024;
    const IS_FIXED_SIZE: bool = false;
}

impl Storable for Association {
    fn to_bytes(&self) -> Cow<[u8]> {
        Cow::Owned(Encode!(self).unwrap())
    }

    fn from_bytes(bytes: Cow<[u8]>) -> Self {
        Decode!(bytes.as_ref(), Self).unwrap()
    }
}

impl BoundedStorable for Association {
    const MAX_SIZE: u32 = 1024;
    const IS_FIXED_SIZE: bool = false;
}

impl Storable for Event {
    fn to_bytes(&self) -> Cow<[u8]> {
        Cow::Owned(Encode!(self).unwrap())
    }

    fn from_bytes(bytes: Cow<[u8]>) -> Self {
        Decode!(bytes.as_ref(), Self).unwrap()
    }
}

impl BoundedStorable for Event {
    const MAX_SIZE: u32 = 1024;
    const IS_FIXED_SIZE: bool = false;
}

impl Storable for MessageToAssociation {
    fn to_bytes(&self) -> Cow<[u8]> {
        Cow::Owned(Encode!(self).unwrap())
    }

    fn from_bytes(bytes: Cow<[u8]>) -> Self {
        Decode!(bytes.as_ref(), Self).unwrap()
    }
}

impl BoundedStorable for MessageToAssociation {
    const MAX_SIZE: u32 = 1024;
    const IS_FIXED_SIZE: bool = false;
}

impl Storable for MentorshipRequest {
    fn to_bytes(&self) -> Cow<[u8]> {
        Cow::Owned(Encode!(self).unwrap())
    }

    fn from_bytes(bytes: Cow<[u8]>) -> Self {
        Decode!(bytes.as_ref(), Self).unwrap()
    }
}

impl BoundedStorable for MentorshipRequest {
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

    static ALUMNI_STORAGE: RefCell<StableBTreeMap<u64, Alumni, Memory>> =
        RefCell::new(StableBTreeMap::init(
            MEMORY_MANAGER.with(|m| m.borrow().get(MemoryId::new(1)))
    ));

    static ASSOCIATIONS_STORAGE: RefCell<StableBTreeMap<u64, Association, Memory>> =
        RefCell::new(StableBTreeMap::init(
            MEMORY_MANAGER.with(|m| m.borrow().get(MemoryId::new(2)))
    ));

    static EVENTS_STORAGE: RefCell<StableBTreeMap<u64, Event, Memory>> =
        RefCell::new(StableBTreeMap::init(
            MEMORY_MANAGER.with(|m| m.borrow().get(MemoryId::new(3)))
    ));

    static MESSAGES_STORAGE: RefCell<StableBTreeMap<u64, MessageToAssociation, Memory>> =
        RefCell::new(StableBTreeMap::init(
            MEMORY_MANAGER.with(|m| m.borrow().get(MemoryId::new(4)))
    ));

    static MENTORSHIP_REQUESTS_STORAGE: RefCell<StableBTreeMap<u64, MentorshipRequest, Memory>> =
        RefCell::new(StableBTreeMap::init(
            MEMORY_MANAGER.with(|m| m.borrow().get(MemoryId::new(5)))
    ));
}

#[derive(candid::CandidType, Deserialize, Serialize)]
struct AlumniPayload {
    name: String,
    email: String,
    graduation_year: u32,
}

// search_alumni Payload
#[derive(candid::CandidType, Deserialize, Serialize)]
struct SearchAlumniPayload {
    name: Option<String>,
    graduation_year: Option<u32>,
}

#[derive(candid::CandidType, Deserialize, Serialize)]
struct AssociationPayload {
    name: String,
    description: String,
}

// Join_association Payload
#[derive(candid::CandidType, Deserialize, Serialize)]
struct JoinAssociationPayload {
    alumni_id: u64,
    association_id: u64,
}

// leave_association Payload
#[derive(candid::CandidType, Deserialize, Serialize)]
struct LeaveAssociationPayload {
    alumni_id: u64,
    association_id: u64,
}

#[derive(candid::CandidType, Deserialize, Serialize)]
struct EventPayload {
    association_id: u64,
    title: String,
    description: String,
    date_time: u64,
    location: String,
    organizer: String,
    capacity: u32,
}

// rsvp_event Payload
#[derive(candid::CandidType, Deserialize, Serialize)]
struct RsvpEventPayload {
    alumni_id: u64,
    event_id: u64,
}

#[derive(candid::CandidType, Deserialize, Serialize)]
struct MessagePayload {
    association_id: u64,
    sender_id: u64,
    content: String,
}

#[derive(candid::CandidType, Deserialize, Serialize)]
struct MentorshipRequestPayload {
    requester_id: u64,
    mentor_id: u64,
}

#[derive(candid::CandidType, Deserialize, Serialize)]
enum Message {
    Success(String),
    Error(String),
    NotFound(String),
    InvalidPayload(String),
}

#[ic_cdk::update]
fn create_alumni(payload: AlumniPayload) -> Result<Alumni, Message> {
    if payload.name.is_empty() || payload.email.is_empty() {
        return Err(Message::InvalidPayload(
            "Ensure 'name' and 'email' are provided.".to_string(),
        ));
    }

    let id = ID_COUNTER
        .with(|counter| {
            let current_value = *counter.borrow().get();
            counter.borrow_mut().set(current_value + 1)
        })
        .expect("Cannot increment ID counter");

    let alumni = Alumni {
        id,
        name: payload.name,
        email: payload.email,
        graduation_year: payload.graduation_year,
        created_at: current_time(),
    };
    ALUMNI_STORAGE.with(|storage| storage.borrow_mut().insert(id, alumni.clone()));
    Ok(alumni)
}

#[ic_cdk::query]
fn get_alumnis() -> Result<Vec<Alumni>, Message> {
    ALUMNI_STORAGE.with(|storage| {
        let alumni: Vec<Alumni> = storage
            .borrow()
            .iter()
            .map(|(_, alumni)| alumni.clone())
            .collect();

        if alumni.is_empty() {
            Err(Message::NotFound("No alumni found".to_string()))
        } else {
            Ok(alumni)
        }
    })
}

#[ic_cdk::query]
fn get_alumni_by_id(id: u64) -> Result<Alumni, Message> {
    ALUMNI_STORAGE.with(|storage| {
        storage
            .borrow()
            .iter()
            .find(|(_, alumni)| alumni.id == id)
            .map(|(_, alumni)| alumni.clone())
            .ok_or(Message::NotFound("Alumni not found".to_string()))
    })
}

#[ic_cdk::update]
fn create_association(payload: AssociationPayload) -> Result<Association, Message> {
    if payload.name.is_empty() || payload.description.is_empty() {
        return Err(Message::InvalidPayload(
            "Ensure 'name' and 'description' are provided.".to_string(),
        ));
    }

    let id = ID_COUNTER
        .with(|counter| {
            let current_value = *counter.borrow().get();
            counter.borrow_mut().set(current_value + 1)
        })
        .expect("Cannot increment ID counter");

    let association = Association {
        id,
        name: payload.name,
        description: payload.description,
        alumnis: vec![],
        created_at: current_time(),
    };
    ASSOCIATIONS_STORAGE.with(|storage| storage.borrow_mut().insert(id, association.clone()));
    Ok(association)
}

#[ic_cdk::query]
fn get_associations() -> Result<Vec<Association>, Message> {
    ASSOCIATIONS_STORAGE.with(|storage| {
        let associations: Vec<Association> = storage
            .borrow()
            .iter()
            .map(|(_, association)| association.clone())
            .collect();

        if associations.is_empty() {
            Err(Message::NotFound("No associations found".to_string()))
        } else {
            Ok(associations)
        }
    })
}

#[ic_cdk::query]
fn get_association_by_id(id: u64) -> Result<Association, Message> {
    ASSOCIATIONS_STORAGE.with(|storage| {
        storage
            .borrow()
            .iter()
            .find(|(_, association)| association.id == id)
            .map(|(_, association)| association.clone())
            .ok_or(Message::NotFound("Association not found".to_string()))
    })
}

#[ic_cdk::update]
fn create_event(payload: EventPayload) -> Result<Event, Message> {
    // Validate the payload to ensure all fields are provided
    if payload.title.is_empty()
        || payload.description.is_empty()
        || payload.location.is_empty()
        || payload.organizer.is_empty()
    {
        return Err(Message::InvalidPayload(
            "Ensure 'title', 'description', 'location', and 'organizer' are provided.".to_string(),
        ));
    }

    // Validate the association id to ensure it exists
    let association = ASSOCIATIONS_STORAGE.with(|storage| {
        storage
            .borrow()
            .iter()
            .find(|(_, association)| association.id == payload.association_id)
            .map(|(_, association)| association.clone())
    });
    if association.is_none() {
        return Err(Message::NotFound("Association not found".to_string()));
    }

    // Ensure the capacity is greater than 0
    if payload.capacity == 0 {
        return Err(Message::InvalidPayload(
            "Ensure 'capacity' is greater than 0.".to_string(),
        ));
    }

    let id = ID_COUNTER
        .with(|counter| {
            let current_value = *counter.borrow().get();
            counter.borrow_mut().set(current_value + 1)
        })
        .expect("Cannot increment ID counter");

    let event = Event {
        id,
        association_id: payload.association_id,
        title: payload.title,
        description: payload.description,
        date_time: payload.date_time,
        location: payload.location,
        organizer: payload.organizer,
        capacity: payload.capacity,
        attendees: vec![],
        created_at: current_time(),
    };
    EVENTS_STORAGE.with(|storage| storage.borrow_mut().insert(id, event.clone()));
    Ok(event)
}

#[ic_cdk::query]
fn get_events() -> Result<Vec<Event>, Message> {
    EVENTS_STORAGE.with(|storage| {
        let events: Vec<Event> = storage
            .borrow()
            .iter()
            .map(|(_, event)| event.clone())
            .collect();

        if events.is_empty() {
            Err(Message::NotFound("No events found".to_string()))
        } else {
            Ok(events)
        }
    })
}

#[ic_cdk::query]
fn get_event_by_id(id: u64) -> Result<Event, Message> {
    EVENTS_STORAGE.with(|storage| {
        storage
            .borrow()
            .iter()
            .find(|(_, event)| event.id == id)
            .map(|(_, event)| event.clone())
            .ok_or(Message::NotFound("Event not found".to_string()))
    })
}

// Function to RSVP to an event
#[ic_cdk::update]
fn rsvp_event(payload: RsvpEventPayload) -> Result<Message, Message> {
    // Validate the user input to ensure all fields are provided
    if payload.alumni_id == 100 || payload.event_id == 100 {
        return Err(Message::InvalidPayload(
            "Ensure 'alumni_id' and 'event_id' are provided.".to_string(),
        ));
    }

    // Validate alumni id to ensure it exists
    let alumni_exists = ALUMNI_STORAGE.with(|storage| {
        storage
            .borrow()
            .iter()
            .any(|(_, alumni)| alumni.id == payload.alumni_id)
    });
    if !alumni_exists {
        return Err(Message::NotFound("Alumni not found".to_string()));
    }

    // Validate event id to ensure it exists
    let event = EVENTS_STORAGE.with(|storage| {
        storage
            .borrow()
            .iter()
            .find(|(_, event)| event.id == payload.event_id)
            .map(|(_, event)| event.clone())
    });
    if event.is_none() {
        return Err(Message::NotFound("Event not found".to_string()));
    }

    // Return an error message if the alumni has already rsvp'd to the event
    let has_rsvp = event
        .as_ref()
        .unwrap()
        .attendees
        .iter()
        .any(|id| id == &payload.alumni_id.to_string());
    if has_rsvp {
        return Err(Message::Error(
            "Alumni has already RSVP'd to the event.".to_string(),
        ));
    }

    // Logic to add alumni to the event's attendee list if the list is not full.
    // If the list is full, return an error message.
    let mut event = event.unwrap();
    if event.attendees.len() as u32 >= event.capacity {
        return Err(Message::Error("Sorry the Event is full.".to_string()));
    }
    event.attendees.push(payload.alumni_id.to_string());
    EVENTS_STORAGE.with(|storage| storage.borrow_mut().insert(payload.event_id, event));

    Ok(Message::Success("RSVP successful.".to_string()))
}

// Function to join an association
#[ic_cdk::update]
fn join_association(payload: JoinAssociationPayload) -> Result<Message, Message> {
    // Validate the user input to ensure all fields are provided
    if payload.alumni_id == 10 || payload.association_id == 0 {
        return Err(Message::InvalidPayload(
            "Ensure 'alumni_id' and 'association_id' are provided.".to_string(),
        ));
    }

    // Validate alumni id to ensure it exists
    let alumni_exists = ALUMNI_STORAGE.with(|storage| {
        storage
            .borrow()
            .iter()
            .any(|(_, alumni)| alumni.id == payload.alumni_id)
    });
    if !alumni_exists {
        return Err(Message::NotFound("Alumni not found".to_string()));
    }

    // Validate association id to ensure it exists
    let association = ASSOCIATIONS_STORAGE.with(|storage| {
        storage
            .borrow()
            .iter()
            .find(|(_, association)| association.id == payload.association_id)
            .map(|(_, association)| association.clone())
    });
    if association.is_none() {
        return Err(Message::NotFound("Association not found".to_string()));
    }

    // Check if the alumni is already a member of the association
    let is_member = association
        .as_ref()
        .unwrap()
        .alumnis
        .iter()
        .any(|&id| id == payload.alumni_id);

    if is_member {
        return Err(Message::Error(
            "Alumni is already a member of the association.".to_string(),
        ));
    }

    // Logic to add alumni to the association's member list
    ASSOCIATIONS_STORAGE.with(|storage| {
        if let Some(mut assoc) = association {
            assoc.alumnis.push(payload.alumni_id);
            storage.borrow_mut().insert(payload.association_id, assoc);
        }
    });

    Ok(Message::Success(
        "Alumni joined the association.".to_string(),
    ))
}

// Function to leave an association
#[ic_cdk::update]
fn leave_association(payload: LeaveAssociationPayload) -> Result<Message, Message> {
    // validate the user input to ensure all fields are provided
    if payload.alumni_id == 10 || payload.association_id == 0 {
        return Err(Message::InvalidPayload(
            "Ensure 'alumni_id' and 'association_id' are provided.".to_string(),
        ));
    }

    // Validate alumni id to ensure it exists
    let alumni_exists = ALUMNI_STORAGE.with(|storage| {
        storage
            .borrow()
            .iter()
            .any(|(_, alumni)| alumni.id == payload.alumni_id)
    });
    if !alumni_exists {
        return Err(Message::NotFound("Alumni not found".to_string()));
    }

    // Validate association id to ensure it exists
    let association = ASSOCIATIONS_STORAGE.with(|storage| {
        storage
            .borrow()
            .iter()
            .find(|(_, association)| association.id == payload.association_id)
            .map(|(_, association)| association.clone())
    });
    if association.is_none() {
        return Err(Message::NotFound("Association not found".to_string()));
    }

    // Logic to remove alumni from the association's member list
    ASSOCIATIONS_STORAGE.with(|storage| {
        if let Some(mut assoc) = association {
            assoc.alumnis.retain(|&id| id != payload.alumni_id);
            storage.borrow_mut().insert(payload.association_id, assoc);
        }
    });

    Ok(Message::Success("Alumni left the association.".to_string()))
}

// Function to send a message to association members
#[ic_cdk::update]
fn send_message_to_association(payload: MessagePayload) -> Result<Message, Message> {
    // Validate the user input to ensure all fields are provided
    if payload.content.is_empty() {
        return Err(Message::InvalidPayload(
            "Ensure 'content' is provided.".to_string(),
        ));
    }

    // Validate sender id to ensure it exists
    let sender = ALUMNI_STORAGE.with(|storage| {
        storage
            .borrow()
            .iter()
            .find(|(_, alumni)| alumni.id == payload.sender_id)
            .map(|(_, alumni)| alumni.clone())
    });
    if sender.is_none() {
        return Err(Message::NotFound("Sender not found".to_string()));
    }

    // Validate association id to ensure it exists
    let association = ASSOCIATIONS_STORAGE.with(|storage| {
        storage
            .borrow()
            .iter()
            .find(|(_, association)| association.id == payload.association_id)
            .map(|(_, association)| association.clone())
    });
    if association.is_none() {
        return Err(Message::NotFound("Association not found".to_string()));
    }

    let id = ID_COUNTER
        .with(|counter| {
            let current_value = *counter.borrow().get();
            counter.borrow_mut().set(current_value + 1)
        })
        .expect("Cannot increment ID counter");

    let message = MessageToAssociation {
        id,
        association_id: payload.association_id,
        sender_id: payload.sender_id,
        content: payload.content,
        created_at: current_time(),
    };
    MESSAGES_STORAGE.with(|storage| storage.borrow_mut().insert(id, message.clone()));
    Ok(Message::Success(
        "Message sent to association members.".to_string(),
    ))
}

// Function to search alumni by name or graduation year
#[ic_cdk::query]
fn search_alumni(payload: SearchAlumniPayload) -> Result<Vec<Alumni>, Message> {
    // Validate the user input to ensure at least one field is provided
    if payload.name.is_none() && payload.graduation_year.is_none() {
        return Err(Message::InvalidPayload(
            "Ensure 'name' or 'graduation_year' is provided.".to_string(),
        ));
    }

    // Logic to search alumni by name or graduation year
    ALUMNI_STORAGE.with(|storage| {
        let alumni: Vec<Alumni> = storage
            .borrow()
            .iter()
            .filter(|(_, alumni)| {
                if let Some(name) = &payload.name {
                    if !alumni.name.contains(name) {
                        return false;
                    }
                }
                if let Some(graduation_year) = payload.graduation_year {
                    if alumni.graduation_year != graduation_year {
                        return false;
                    }
                }
                true
            })
            .map(|(_, alumni)| alumni.clone())
            .collect();

        if alumni.is_empty() {
            Err(Message::NotFound("No alumni found".to_string()))
        } else {
            Ok(alumni)
        }
    })
}

// Function to request mentorship
#[ic_cdk::update]
fn request_mentorship(payload: MentorshipRequestPayload) -> Result<MentorshipRequest, Message> {
    // Validate the requester to ensure it exists
    let requester = ALUMNI_STORAGE.with(|storage| {
        storage
            .borrow()
            .iter()
            .find(|(_, alumni)| alumni.id == payload.requester_id)
            .map(|(_, alumni)| alumni.clone())
    });
    if requester.is_none() {
        return Err(Message::NotFound("Requester not found".to_string()));
    }

    // Validate the mentor to ensure it exists
    let mentor = ALUMNI_STORAGE.with(|storage| {
        storage
            .borrow()
            .iter()
            .find(|(_, alumni)| alumni.id == payload.mentor_id)
            .map(|(_, alumni)| alumni.clone())
    });
    if mentor.is_none() {
        return Err(Message::NotFound("Mentor not found".to_string()));
    }

    // Ensure that the alumni cannot mentor themselves
    if payload.requester_id == payload.mentor_id {
        return Err(Message::Error("You cannot mentor yourself.".to_string()));
    }

    // Logic to create a mentorship request
    let id = ID_COUNTER
        .with(|counter| {
            let current_value = *counter.borrow().get();
            counter.borrow_mut().set(current_value + 1)
        })
        .expect("Cannot increment ID counter");

    let mentorship_request = MentorshipRequest {
        id,
        requester_id: payload.requester_id,
        mentor_id: payload.mentor_id,
        status: "pending".to_string(),
        created_at: current_time(),
    };
    MENTORSHIP_REQUESTS_STORAGE
        .with(|storage| storage.borrow_mut().insert(id, mentorship_request.clone()));
    Ok(mentorship_request)
}

// Function to approve mentorship request
#[ic_cdk::update]
fn approve_mentorship_request(request_id: u64) -> Result<Message, Message> {
    // Validate request ID to ensure it exists
    let mentorship_request = MENTORSHIP_REQUESTS_STORAGE.with(|storage| {
        storage
            .borrow()
            .iter()
            .find(|(_, request)| request.id == request_id)
            .map(|(_, request)| request.clone())
    });
    if mentorship_request.is_none() {
        return Err(Message::NotFound(
            "Mentorship request not found".to_string(),
        ));
    }

    // Update the request status to "approved"
    let mut request = mentorship_request.unwrap();
    request.status = "approved".to_string();
    MENTORSHIP_REQUESTS_STORAGE.with(|storage| storage.borrow_mut().insert(request_id, request));

    Ok(Message::Success("Mentorship request approved.".to_string()))
}

fn current_time() -> u64 {
    time()
}

#[derive(candid::CandidType, Deserialize, Serialize)]
enum Error {
    NotFound { msg: String },
    UnAuthorized { msg: String },
}

ic_cdk::export_candid!();
