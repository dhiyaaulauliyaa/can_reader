use can_dbc::DBC;
use canparse::pgn::{ParseMessage, PgnLibrary};
use log::error;
use socketcan::EmbeddedFrame;
use socketcan::Id;
use socketcan::{CanSocket, Socket};
use std::collections::HashMap;
use std::fs::File;
use std::io::prelude::*;
use std::sync::Arc;
use std::sync::Mutex;
use std::thread;
use std::time::Duration;

fn main() {
    let dbc_file_path = "/usr/share/can-dbcs/consolidated.dbc";

    let mut dbc_file = File::open(dbc_file_path).expect("DBC file not found");
    let mut dbc_file_buffer = Vec::new();
    dbc_file
        .read_to_end(&mut dbc_file_buffer)
        .expect("Failed to open DBC file");

    let dbc = can_dbc::DBC::from_slice(&dbc_file_buffer).expect("Failed to parse dbc file");

    let pgn_lib = match PgnLibrary::from_dbc_file(dbc_file_path) {
        Ok(lib) => lib,
        Err(e) => {
            error!("Couldn't parse DBC from buffer: {}", e);
            return;
        }
    };

    let message_filter = vec![
        "vcu_status_pkt_10",
        "vcu_status_pkt_3",
        "vcu_status_pkt_4",
        "vcu_status_pkt_5",
        "vcu_err_pkt_1",
        "vcu_ble_pkt_1",
        "vcu_status_pkt_8",
        "vcu_screen_controller",
        "vcu_status_pkt_13",
        "vcu_status_pkt_1",
        "tpms_status_pkt",
        "screen_brightness_pkt",
        "vcu_ota_pkt",
    ];

    let mut packets_hash_map: HashMap<u32, (PgnLibrary, Vec<String>)> = HashMap::new();
    for message in dbc.messages() {
        let message_name = message.message_name();
        let include_message = message_filter.iter().find(|&&item| item == message_name);
        if include_message.is_none() {
            log::info!("Message not included in filter {:?}", message_name);
            continue;
        }

        let message_id: u32 = match message.message_id() {
            can_dbc::MessageId::Standard(id) => *id as u32,
            can_dbc::MessageId::Extended(id) => *id,
        };

        let mut values_vec: Vec<String> = Vec::new();
        for signal in message.signals() {
            values_vec.push(signal.name().to_owned());
        }

        packets_hash_map.insert(
            message_id,
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

                /* Process CAN Data */
                let mut can_data = frame.data();
                let mut can_data_vec = frame.data().to_vec();

                if can_data.len() < 8 {
                    let mut zero_vec: Vec<u8> = vec![0; 8 - can_data.len()];
                    can_data_vec.append(&mut zero_vec);
                    can_data = &can_data_vec;
                }

                /* Parse CAN Frame */
                match &packets_hash_map.get(&can_id) {
                    None => continue,
                    Some((pgn_lib, spns)) => {
                        let mut can_frame_map: HashMap<&str, f32> = HashMap::new();
                        for spn in spns.iter() {
                            let spn_def = match pgn_lib.get_spn(spn) {
                                Some(def) => def,
                                None => {
                                    error!("Couldn't get SPN definition for: {}", spn);
                                    continue;
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
