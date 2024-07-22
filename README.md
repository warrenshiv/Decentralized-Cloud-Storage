# Decentralized Cloud Storage

Decentralized Cloud Storage is a blockchain-based cloud storage solution implemented in Rust. This project leverages Internet Computer (IC) technology to provide a secure, decentralized, and user-friendly platform for managing and sharing files.

## Features

- **User Management**
  - Create and manage user accounts with roles and permissions.
  - Enable or disable two-factor authentication for enhanced security.

- **File Management**
  - Upload, download, and manage files with versioning and tagging.
  - Store files with encryption for added security.
  - Implement file versioning to keep track of changes and allow rollbacks.

- **Access Control**
  - Set fine-grained access controls for files, including read and write permissions.
  - Add expiry dates to access controls for temporary file sharing.

- **Audit Logging**
  - Maintain audit logs to track user actions and ensure accountability.

- **File Search**
  - Search files based on tags for easy retrieval and organization.

## Getting Started

Follow these steps to get started with Decentralized Cloud Storage:

1. **Install Dependencies:**
   - Ensure you have Rust and the DFINITY SDK installed on your machine.
   - Install necessary Rust crates by running `cargo build`.

2. **Deploy the Canister:**
   - Run `npm run gen-deploy` to generate and deploy the canister.

3. **Interact with the Canister:**
   - Use the provided APIs to interact with the canister for user and file management.

## Usage

Here are some example payloads for interacting with the APIs:

### Creating a User

```json

{
    "username": "john_doe",
    "email": "john.doe@example.com",
    "role": "admin"
}

```
### Uploading a File

```json
{
    "owner_id": 1001,
    "filename": "example.txt",
    "content": [72, 101, 108, 108, 111, 32, 87, 111, 114, 108, 100],
    "encrypted": false,
    "tags": ["example", "text"]
}
```

`content`: The content of the file should be in byte array format (example: [72, 101, 108, 108, 111, 32, 87, 111, 114, 108, 100], which represents the string "Hello World").

### Setting Access Control
```json
{
    "file_id": 1,
    "user_id": 1002,
    "read": true,
    "write": false,
    "expiry": null
}
```
### Enabling Two-Factor Authentication
```json
{
    "user_id": 1001
}
```

### Searching Files by Tag
```json
{
    "tag": "example"
}
```


## Requirements
* rustc 1.64 or higher
```bash
$ curl --proto '=https' --tlsv1.2 https://sh.rustup.rs -sSf | sh
$ source "$HOME/.cargo/env"
```
* rust wasm32-unknown-unknown target
```bash
$ rustup target add wasm32-unknown-unknown
```
* candid-extractor
```bash
$ cargo install candid-extractor
```
* install `dfx`
```bash
$ DFX_VERSION=0.15.0 sh -ci "$(curl -fsSL https://sdk.dfinity.org/install.sh)"
$ echo 'export PATH="$PATH:$HOME/bin"' >> "$HOME/.bashrc"
$ source ~/.bashrc
$ dfx start --background
```

If you want to start working on your project right away, you might want to try the following commands:

```bash
$ cd icp_rust_boilerplate/
$ dfx help
$ dfx canister --help
```

## Update dependencies

update the `dependencies` block in `/src/{canister_name}/Cargo.toml`:
```
[dependencies]
candid = "0.9.9"
ic-cdk = "0.11.1"
serde = { version = "1", features = ["derive"] }
serde_json = "1.0"
ic-stable-structures = { git = "https://github.com/lwshang/stable-structures.git", branch = "lwshang/update_cdk"}
```

## did autogenerate

Add this script to the root directory of the project:
```
https://github.com/buildwithjuno/juno/blob/main/scripts/did.sh
```

Update line 16 with the name of your canister:
```
https://github.com/buildwithjuno/juno/blob/main/scripts/did.sh#L16
```

After this run this script to generate Candid.
Important note!

You should run this script each time you modify/add/remove exported functions of the canister.
Otherwise, you'll have to modify the candid file manually.

Also, you can add package json with this content:
```
{
    "scripts": {
        "generate": "./did.sh && dfx generate",
        "gen-deploy": "./did.sh && dfx generate && dfx deploy -y"
      }
}
```

and use commands `npm run generate` to generate candid or `npm run gen-deploy` to generate candid and to deploy a canister.

## Running the project locally

If you want to test your project locally, you can use the following commands:

```bash
# Starts the replica, running in the background
$ dfx start --background

# Deploys your canisters to the replica and generates your candid interface
$ dfx deploy
```