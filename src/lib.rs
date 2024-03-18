/*
* Copyright (C) 2019-2021 TON Labs. All Rights Reserved.
*
* Licensed under the SOFTWARE EVALUATION License (the "License"); you may not use
* this file except in compliance with the License.
*
* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific TON DEV software governing permissions and
* limitations under the License.
*/

#![cfg_attr(feature = "ci_run", deny(warnings))]

#[macro_use]
pub mod types;
#[macro_use]
pub mod stack;
#[macro_use]
pub mod executor;

pub mod smart_contract_info;
pub use self::smart_contract_info::SmartContractInfo;
pub mod error;
pub mod utils;
mod test;

include!("../common/src/info.rs");
