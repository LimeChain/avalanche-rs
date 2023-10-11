// use std::io;
// use std::io::{Error, ErrorKind};
// use crate::message;
// use crate::proto::p2p;
//
// pub struct DeserializedMessage {
//     pub message_type: p2p::message::Message,
//     pub message: p2p::Message,
// }
// // TODO: Add more message types and improve
// pub fn parse_message(bytes: &[u8]) -> io::Result<DeserializedMessage>  {
//     let message = p2p::Message::default();
//
//     let p2p_msg: p2p::Message = prost::Message::decode(bytes).map_err(|e| {
//         Error::new(
//             ErrorKind::InvalidData,
//             format!("failed prost::Message::decode '{}'", e),
//         )
//     })?;
//
//     return match p2p_msg.message.unwrap() {
//         p2p::message::Message::Version(msg) => {
//             Ok(DeserializedMessage {
//                 message_type: p2p::message::Message::Version(msg.clone()),
//                 message,
//             })
//         }
//         _ => {
//             Err(io::Error::new(io::ErrorKind::Other, "Unknown message type"))
//         }
//     };
// }
//
// #[cfg(test)]
// mod tests {
//     use super::*;
//     #[test]
//     pub fn test_parse_version_message() {
//         println!("test_parse_version_message");
//         let bytes = hex::decode("128d2628b52ffd60b8131d98005c2c0172b5290ae40d0aa1093082049d30820285a003020102020100300d06092a864886f70d01010b050030003020170d393931323331305a180f32313230303931343136353635375a3000308202220105000382020f0a0282020100ceaaf95697095a0c978dd134ccaea76c5a3762d087179071d094508692e62f95c055b6d092491154004988148064c425a2629604d6bffda13f7258760cfc1d73a8e20af4d33abf959f3adbca9b22765fcaeeb997d10668f057156057b0641d54d091702344e5c68b56d807986d6be7b02ecb2c37f9e566c6212e32a8aeee140f20f847a40d83f8b3772e49565ac5e0878a0e16fc9b9dd3d75c25378ca6bf9310a02801f2269a0ded740fd86cde879f0c9a5e23117b19fd2122a8e5287466db966a92edc77434ea8d3cdf5e87be379470eda39c8afe2cdf4d9232c72ba1611f04d3085bf94954702ca50c62a4cb9f6a5c2e58e734d16d5d2f3eec45baafb17dbb14db9f7ed99ec04986f46cfd2159c7b8c0935b8a6b784c38094cfa3fa84adcefa970871b015a38f4e86402b6dbad545d34a941dabe850ddbd1bd2f6ba3dda9f5cfeab139079761658fd9d0d9078494795370f7951dda51e948a1b417aeebd65472f764f4261d795c5fd23aa90b3e2c8501e9afe5d48fc6223866bca618edfe990f9263833f7bfd336239264044313e4d34e3532d05f4a93094a392c556fc34754b8698e7f9a84d290547e0de3543585d0d250ab50de90a94b30158e62c9c5d9fea7506b22cf30bd30753cfe3f1b0b5b9a18e8af4b32bbb9fd2830538f5b0b309b6f573f20ce3feb99adac21f7a64cfac55dbbbf1ae718c4a6f6eadaa34f514250203010001a320301e300e0603551d0f0101ff0404030204b0300c13023003696a37733078a71cfcfd4a9bc648d31fdc7122e3112f77a34586fe55fc3f4af350dc0ef6d94c468fcb198d0758331e2c896e2ed99e79a1313ab9db88b482a32c5126526ac06024898eabe8e08cd71df3c67fb036df095d0d6e2029f2b9dd71e862a6c070182c7f057e3e94ae90cc4fbf0a965204440943bf534968ed57d5f43c47403225c597292bbfeb28d28c74e19ba9037e813bee6f3a6acca5416674cdf09725a375249c93fb5bd5237f5d61028b68fb052d14f64ffaafb38b83dccb993d1b84f2e94df08d64f8a20ba0e8420385bd607b30e4aa23400f6d88a4d8556bd0d3e240c86319cd75326e27ba96d94a0c4d871b7e605f1796cf5692a60ea1796244e9ad6c6a0269827651667df6746530902a978cff49086621758d22e961a24249bcffbb3730a37fcaba3766183556d0098da45a23c22460021a423421cdb8e21bdb32b399fbac2261833e4b4f0cad1702ba695697e1a4e416633b39b79713a9371159af015c404e515d25a6ebe15b4cc54f070f036d6e76d81315ab05045119f7c6f1cab0bc8d511a2da2c722b49726ab892dc2bac00e56769394406504d926db73f5c507b933ad737f07045524bec284e1ad24aec73361f0cf6367d675d1226ee5796e0467ef55ac562bda738dc6cfdb8ef66a5360c50685cec6b2965cbde80ccf8ea9404404cd71059e1d3e6edd7466f3dbf47fad79872d4104984fdf7f93121000ffff036a198b18b34b20d9e797a9062a8004784e252771a1966127c53f594f90d794b6147c5418868cbadc2fc969e0b88e0ea0e94ac8a213a91c5d462298ea52c87e925da22b6417c5d5a5f8f919da7ccc0d585e9ff3b4dda08a31a7c255f6d304006d58597dd20c96e98804c8f0a95f8673a487a31015f6b0541db288264fbf5be93d322ca3847abef0aa02783a30cf8f58454cae5a600fc8f8aa5ab0f5932ee39b470932795ff496c5ca76a8fbe0609477de71b594dd7c8fb917a6c038217729f73efda18e4398ccca9610b5b42644afcd2fc55c77cb494d4628dc977a206e4325e0fbfa5e25a7cd724e8b3d275b6414eac5c9e7934c3b32ad1aa14fe2df556d6df30b74dfc1ac8098ad1866e3760517a9d99209fb6ddda7f8d92aeeac25acdb139a677549ef6d81bfe8063568e3eec8f1b6faee405059e3c59403c3f42d626c78961aa122c898fa068398f46f3e4d1ffef4021df2579be4c15e17dc9431e38579635bf6fdb123bb3079462448480943e2d4af743177e18d9ce1df1fef8ae9483d293eca071e29570b5b5b9a0bbe87a5ba6a150daba5fc408df43e060ba19475fa2e4f1674b4e62dd6a9a92bdb85948f2b75f2bf7ee4b7383c5c6d67b62a387c98fd22cf51751f16716d36013b8c3472f3f17f0305e0ed18dc86f77e867091e9fc4d9e7795f1f61e6395cd55a6eaf928b1715a658db6edcc89eb62d1b8e93edd1c89572b66b5f2ab8416ad1f5dd2fdf96d32207eb0bc8e843d8063cc313124c3734bb83c8be02b5463681c4be29696472f374d34c0269a4a61c3fa0f76c2dfecb880a725b2d7dd130ac6117405d98d777b9b2a7eda662b24c1822f8bcf45e7a72defeb56e0a1c85c65c77d6231daa305a01db9b464f39957f8ce1768783d77e0392c2b93c66113f230e8b7e6548290c38be479afbd1569b1c9e107bc5a6be7cb60678e5e3097b0b8ff454822a9e411ad5a57dbd25d34780f9788aa5e07d45e2126e7fbefa13f93e296aa51c599e33bf5962bf278c02855f9168dcb5e023096eb56a08fe1d9ce0cffbad49897d5c85078d2ddbeee81f032eb472547eea6ffd6081184fee7a552946a9cd744245d19b5e126510cd232eb8e7aff7c956cf0fd2ce63c97804b7c8553a506a9f773da3a30e146a760690ed06b9bf9c3e56f7a5d885684a7861c9c91821db96a612ed5daa4cb0bc0dec48eeb582f847bb28fd0c5c97fc1ba60d761d0a8fb4f229a73a170f0a841bb269e03c7aac7575e4bf5c978b72bbfa46e33d7ae02f8009a00acddc905223400a3ad2560b86fd9b5d2f5cd0ca194435ffe2e337a179f07d0616dbafc330cf4c41de26bc226292dd8925b29812aabced734a91614b11ca371ce7b69c1cc0ac32c77bd27627e16d91992126ca2d8e5e1decaa626117fc2b91e19122f9cf98c24835647f3669eb63b40eaa14344f1bfbec828df9b6481a8445329f9fc72ed20bb572e8393103a87ff68e170fe3e0ac05bb2c9518db4769bd1fe09ac9bef023a60816b2f025ec311be04a67e6c73c04f9ec98a4e4734e7a38f64088d7462d116634ef2360df2a401197313287b5def0e48606b7f317e63019998a22dd7be203385127bfa359b16104970efb322a031160b6bd779115fc1ed1543a75b1cce2e94139791a1721a1e225a9d1e49e3a359afd0232d6f3d77f0b1d4f7d0f66192bed3c0960d")
//             .expect("Failed to decode hex string");
//
//         if let Ok(result) = parse_message(&bytes) {
//             match result.message_type {
//                 p2p::message::Message::PeerList(_) => {
//                     println!("Peer list message");
//                 },
//                 p2p::message::Message::Version(_) => {
//                     println!("Version message");
//                 },
//                 p2p::message::Message::Ping(_) => {
//                     println!("Ping message");
//                 },
//                 p2p::message::Message::Pong(_) => {
//                     println!("Pong message");
//                 },
//                 _ => {
//                     println!("Unknown message type");
//                 }
//             }
//         }
//
//         assert!(true)
//     }
// }
