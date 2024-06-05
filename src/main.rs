use canparse::pgn::{ParseMessage, PgnLibrary};
use log::error;
use socketcan::EmbeddedFrame;
use socketcan::Id;
use socketcan::{CanSocket, Socket};
use std::collections::HashMap;
use std::fs::File;
use std::io::prelude::*;
use std::thread;
use std::time::Duration;

fn main() {
    // Prepare DBC File
    let mut packets_hash_map: HashMap<String, (PgnLibrary, Vec<String>)> = HashMap::new();
    let dbc_file_path = "/usr/share/can-dbcs/consolidated.dbc";
    let mut file = match File::open(dbc_file_path) {
        Ok(file) => file,
        Err(e) => {
            error!("Failed to open dbc file: {}", e);
            return; // Exit the function early if the file cannot be opened
        }
    };

    let mut file_string = String::new();
    // Read the file to string and handle potential errors
    if let Err(e) = file.read_to_string(&mut file_string) {
        error!("Failed to read the dbc file into a string: {}", e);
        return; // Exit the function early if reading fails
    }

    let buffer = file_string.as_bytes();
    let dbc = match can_dbc::DBC::from_slice(buffer) {
        Ok(dbc) => dbc,
        Err(_e) => {
            error!("Failed to parse dbc file");
            return;
        }
    };

    let pgn_lib = match PgnLibrary::from_dbc_file(dbc_file_path) {
        Ok(lib) => lib,
        Err(e) => {
            error!("Couldn't parse DBC from buffer: {}", e);
            return;
        }
    };

    let dbc_messages = dbc.messages().to_owned();
    for message in dbc_messages {
        let mut values_vec: Vec<String> = Vec::new();
        for signal in message.signals() {
            let signal_name = signal.name().to_owned();
            let signal_name_str = signal_name.as_str();
            values_vec.push(signal_name_str.to_owned());
        }
        let message_id: u32 = match message.message_id() {
            can_dbc::MessageId::Standard(id) => *id as u32,
            can_dbc::MessageId::Extended(id) => *id,
        };

        packets_hash_map.insert(
            format!("0x{:08x}", message_id),
            (pgn_lib.to_owned(), values_vec),
        );
    }

    // Open CAN socket
    let can_interface = "vcan0";
    let can_socket = match CanSocket::open(can_interface) {
        Ok(socket) => socket,
        Err(e) => {
            error!("Failed to open CAN socket: {}", e);
            panic!();
        }
    };

    loop {
        match can_socket.read_frame() {
            Err(e) => {
                error!("Failed to read CAN frame: {}", e);
                thread::sleep(Duration::from_secs(1)); // Sleep to avoid tight loop on errors
            }
            Ok(frame) => {
                /* Process ID */
                let can_id = match frame.id() {
                    Id::Standard(id) => id.as_raw() as u32,
                    Id::Extended(id) => id.as_raw(),
                };
                // let raw_can_id_string = match frame.id() {
                //     Id::Standard(id) => format!("{:X}", id.as_raw()),
                //     Id::Extended(id) => format!("{:X}", id.as_raw()),
                // };

                /* Process CAN Data */
                let mut can_data = frame.data();
                let mut can_data_vec = frame.data().to_vec();

                if can_data.len() < 8 {
                    let mut zero_vec: Vec<u8> = vec![0; 8 - can_data.len()];
                    can_data_vec.append(&mut zero_vec);
                    can_data = &can_data_vec;
                }

                let id: String = format!("0x{:08x}", can_id);
                match &packets_hash_map.get(&id) {
                    None => {
                        error!("id not found {:?}", id);
                    }
                    Some((pgn_lib, spns)) => {
                        let mut can_frame_map: HashMap<&str, f32> = HashMap::new();
                        for spn in spns.iter() {
                            let spn_def = match pgn_lib.get_spn(spn) {
                                Some(def) => def,
                                None => {
                                    error!("Couldn't get SPN definition for: {}", spn);
                                    continue; // Skip this iteration if SPN is critical to further processing
                                }
                            };
                            let spn_value = spn_def.parse_message(can_data);
                            if let Some(value) = spn_value {
                                can_frame_map.insert(spn, value);
                            }
                        }
                        println!("{:?}", can_frame_map);
                    }
                }
            }
        }
    }
}
