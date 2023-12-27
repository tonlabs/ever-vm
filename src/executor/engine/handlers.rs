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

use crate::{
    error::TvmError,
    executor::{
        engine::{Engine, core::ExecuteHandler, storage::fetch_stack},
        accounts::*,
        blockchain::*, config::*, continuation::*, crypto::*, currency::*, deserialization::*,
        dictionary::*, dump::*, exceptions::*, gas::*, globals::*, math::*, null::*,
        rand::*, serialization::*, slice_comparison::*, stack::*, tuple::*,
        types::{InstructionOptions, Instruction}
    },
    stack::integer::behavior::{Signaling, Quiet},
    types::{Exception, Status}
};
#[cfg(feature = "gosh")]
use crate::executor::diff::*;
use std::{fmt, ops::Range};
use ton_types::{error, Result, types::ExceptionCode};

// ( - )
fn execute_nop(engine: &mut Engine) -> Status {
    engine.load_instruction(Instruction::new("NOP"))
}

fn execute_setcp(engine: &mut Engine) -> Status {
    engine.load_instruction(
        Instruction::new("SETCP").set_opts(InstructionOptions::Integer(-15..240))
    )?;
    let code_page = engine.cmd.integer();
    *engine.code_page_mut() = code_page;
    Ok(())
}

fn execute_setcpx(engine: &mut Engine) -> Status {
    engine.load_instruction(
        Instruction::new("SETCPX")
    )?;
    fetch_stack(engine, 1)?;
    let code_page = engine.cmd.var(0).as_integer()?.into(-1<<15..=1<<(15 - 1))?;
    *engine.code_page_mut() = code_page;
    Ok(())
}

fn execute_unknown(engine: &mut Engine) -> Status {
    let code = engine.last_cmd();
    log::trace!(target: "tvm", "Invalid code: {} ({:#X})\n", code, code);
    err!(ExceptionCode::InvalidOpcode)
}

#[derive(Clone, Copy)]
enum Handler {
    Direct(ExecuteHandler),
    Subset(usize),
}

#[derive(Clone)]
pub struct Handlers {
    directs: [Option<Handler>; 256],
    subsets: Vec<Handlers>,
}


impl Handlers {
    const fn new() -> Handlers {
        Handlers {
            directs: [None; 256],
            subsets: Vec::new(),
        }
    }

    pub(super) fn new_code_page_0() -> Handlers {
        let mut handlers = Handlers::new();
        handlers
            .add_code_page_0_part_stack()
            .add_code_page_0_tuple()
            .add_code_page_0_part_constant()
            .add_code_page_0_arithmetic()
            .add_code_page_0_comparsion()
            .add_code_page_0_cell()
            .add_code_page_0_control_flow()
            .add_code_page_0_exceptions()
            .add_code_page_0_dictionaries()
            .add_code_page_0_gas_rand_config()
            .add_code_page_0_blockchain()
            .add_code_page_0_crypto()
            .add_code_page_0_debug()
            .add_subset(0xFF, Handlers::new()
                .set_range(0x00..0xF0, execute_setcp)
                .set(0xF0, execute_setcpx)
                .set_range(0xF1..0xFF, execute_setcp)
                .set(0xFF, execute_setcp)
            );
        handlers
    }

    fn add_code_page_0_part_stack(&mut self) -> &mut Handlers {
        self
            .set(0x00, execute_nop)
            .set(0x01, execute_swap)
            .set_range(0x02..0x10, execute_xchg_simple)
            .set(0x10, execute_xchg_std)
            .set(0x11, execute_xchg_long)
            .set_range(0x12..0x20, execute_xchg_simple)
            .set_range(0x20..0x30, execute_push)
            .set_range(0x30..0x40, execute_pop)
            .set_range(0x40..0x50, execute_xchg3)
            .set(0x50, execute_xchg2)
            .set(0x51, execute_xcpu)
            .set(0x52, execute_puxc)
            .set(0x53, execute_push2)
            .add_subset(0x54, Handlers::new()
                .set_range(0x00..0x10, execute_xchg3)
                .set_range(0x10..0x20, execute_xc2pu)
                .set_range(0x20..0x30, execute_xcpuxc)
                .set_range(0x30..0x40, execute_xcpu2)
                .set_range(0x40..0x50, execute_puxc2)
                .set_range(0x50..0x60, execute_puxcpu)
                .set_range(0x60..0x70, execute_pu2xc)
                .set_range(0x70..0x80, execute_push3)
            )
            .set(0x55, execute_blkswap)
            .set(0x56, execute_push)
            .set(0x57, execute_pop)
            .set(0x58, execute_rot)
            .set(0x59, execute_rotrev)
            .set(0x5A, execute_swap2)
            .set(0x5B, execute_drop2)
            .set(0x5C, execute_dup2)
            .set(0x5D, execute_over2)
            .set(0x5E, execute_reverse)
            .add_subset(0x5F, Handlers::new()
                .set_range(0x00..0x10, execute_blkdrop)
                .set_range(0x10..0xFF, execute_blkpush)
                .set(0xFF, execute_blkpush)
            )
            .set(0x60, execute_pick)
            .set(0x61, execute_roll)
            .set(0x62, execute_rollrev)
            .set(0x63, execute_blkswx)
            .set(0x64, execute_revx)
            .set(0x65, execute_dropx)
            .set(0x66, execute_tuck)
            .set(0x67, execute_xchgx)
            .set(0x68, execute_depth)
            .set(0x69, execute_chkdepth)
            .set(0x6A, execute_onlytopx)
            .set(0x6B, execute_onlyx)
            .add_subset(0x6C, Handlers::new()
                .set_range(0x10..0xFF, execute_blkdrop2)
                .set(0xFF, execute_blkdrop2)
            )
    }

    fn add_code_page_0_tuple(&mut self) -> &mut Handlers {
        self
            .set(0x6D, execute_null)
            .set(0x6E, execute_isnull)
            .add_subset(0x6F, Handlers::new()
                .set_range(0x00..0x10, execute_tuple_create)
                .set_range(0x10..0x20, execute_tuple_index)
                .set_range(0x20..0x30, execute_tuple_un)
                .set_range(0x30..0x40, execute_tuple_unpackfirst)
                .set_range(0x40..0x50, execute_tuple_explode)
                .set_range(0x50..0x60, execute_tuple_setindex)
                .set_range(0x60..0x70, execute_tuple_index_quiet)
                .set_range(0x70..0x80, execute_tuple_setindex_quiet)
                .set(0x80, execute_tuple_createvar)
                .set(0x81, execute_tuple_indexvar)
                .set(0x82, execute_tuple_untuplevar)
                .set(0x83, execute_tuple_unpackfirstvar)
                .set(0x84, execute_tuple_explodevar)
                .set(0x85, execute_tuple_setindexvar)
                .set(0x86, execute_tuple_indexvar_quiet)
                .set(0x87, execute_tuple_setindexvar_quiet)
                .set(0x88, execute_tuple_len)
                .set(0x89, execute_tuple_len_quiet)
                .set(0x8A, execute_istuple)
                .set(0x8B, execute_tuple_last)
                .set(0x8C, execute_tuple_push)
                .set(0x8D, execute_tuple_pop)
                .set(0x90, execute_zeroswapif)
                .set(0x91, execute_zeroswapifnot)
                .set(0x92, execute_zerorotrif)
                .set(0x93, execute_zerorotrifnot)
                .set(0x94, execute_zeroswapif2)
                .set(0x95, execute_zeroswapifnot2)
                .set(0x96, execute_zerorotrif2)
                .set(0x97, execute_zerorotrifnot2)
                .set(0xA0, execute_nullswapif)
                .set(0xA1, execute_nullswapifnot)
                .set(0xA2, execute_nullrotrif)
                .set(0xA3, execute_nullrotrifnot)
                .set(0xA4, execute_nullswapif2)
                .set(0xA5, execute_nullswapifnot2)
                .set(0xA6, execute_nullrotrif2)
                .set(0xA7, execute_nullrotrifnot2)
                .set_range(0xB0..0xC0, execute_tuple_index2)
                .set_range(0xC0..0xFF, execute_tuple_index3)
                .set(0xFF, execute_tuple_index3)
            )
    }

    fn add_code_page_0_part_constant(&mut self) -> &mut Handlers {
        self
            .set_range(0x70..0x82, execute_pushint)
            .set(0x82, execute_pushint_big)
            .add_subset(0x83, Handlers::new()
                .set_range(0x00..0xFF, execute_pushpow2)
                .set(0xFF, execute_pushnan)
            )
            .set(0x84, execute_pushpow2dec)
            .set(0x85, execute_pushnegpow2)
            .set(0x88, execute_pushref)
            .set(0x89, execute_pushrefslice)
            .set(0x8A, execute_pushrefcont)
            .set(0x8B, execute_pushslice_short)
            .set(0x8C, execute_pushslice_mid)
            .set(0x8D, execute_pushslice_long)
            .set_range(0x8E..0x90, execute_pushcont_short)
            .set_range(0x90..0xA0, execute_pushcont_long)
    }

    fn add_code_page_0_arithmetic(&mut self) -> &mut Handlers {
        self
            .set(0xA0, execute_add::<Signaling>)
            .set(0xA1, execute_sub::<Signaling>)
            .set(0xA2, execute_subr::<Signaling>)
            .set(0xA3, execute_negate::<Signaling>)
            .set(0xA4, execute_inc::<Signaling>)
            .set(0xA5, execute_dec::<Signaling>)
            .set(0xA6, execute_addconst::<Signaling>)
            .set(0xA7, execute_mulconst::<Signaling>)
            .set(0xA8, execute_mul::<Signaling>)
            .set(0xA9, execute_divmod::<Signaling>)
            .set(0xAA, execute_lshift::<Signaling>)
            .set(0xAB, execute_rshift::<Signaling>)
            .set(0xAC, execute_lshift::<Signaling>)
            .set(0xAD, execute_rshift::<Signaling>)
            .set(0xAE, execute_pow2::<Signaling>)
            //0xB0
            .set(0xB0, execute_and::<Signaling>)
            .set(0xB1, execute_or::<Signaling>)
            .set(0xB2, execute_xor::<Signaling>)
            .set(0xB3, execute_not::<Signaling>)
            .set(0xB4, execute_fits::<Signaling>)
            .set(0xB5, execute_ufits::<Signaling>)
            .add_subset(0xB6, Handlers::new()
                .set(0x00, execute_fitsx::<Signaling>)
                .set(0x01, execute_ufitsx::<Signaling>)
                .set(0x02, execute_bitsize::<Signaling>)
                .set(0x03, execute_ubitsize::<Signaling>)
                .set(0x08, execute_min::<Signaling>)
                .set(0x09, execute_max::<Signaling>)
                .set(0x0A, execute_minmax::<Signaling>)
                .set(0x0B, execute_abs::<Signaling>)
            )
            .add_subset(0xB7, Handlers::new()
                .set(0xA0, execute_add::<Quiet>)
                .set(0xA1, execute_sub::<Quiet>)
                .set(0xA2, execute_subr::<Quiet>)
                .set(0xA3, execute_negate::<Quiet>)
                .set(0xA4, execute_inc::<Quiet>)
                .set(0xA5, execute_dec::<Quiet>)
                .set(0xA6, execute_addconst::<Quiet>)
                .set(0xA7, execute_mulconst::<Quiet>)
                .set(0xA8, execute_mul::<Quiet>)
                .set(0xA9, execute_divmod::<Quiet>)
                .set(0xAA, execute_lshift::<Quiet>)
                .set(0xAB, execute_rshift::<Quiet>)
                .set(0xAC, execute_lshift::<Quiet>)
                .set(0xAD, execute_rshift::<Quiet>)
                .set(0xAE, execute_pow2::<Quiet>)
                .set(0xB0, execute_and::<Quiet>)
                .set(0xB1, execute_or::<Quiet>)
                .set(0xB2, execute_xor::<Quiet>)
                .set(0xB3, execute_not::<Quiet>)
                .set(0xB4, execute_fits::<Quiet>)
                .set(0xB5, execute_ufits::<Quiet>)
                .add_subset(0xB6, Handlers::new()
                    .set(0x00, execute_fitsx::<Quiet>)
                    .set(0x01, execute_ufitsx::<Quiet>)
                    .set(0x02, execute_bitsize::<Quiet>)
                    .set(0x03, execute_ubitsize::<Quiet>)
                    .set(0x08, execute_min::<Quiet>)
                    .set(0x09, execute_max::<Quiet>)
                    .set(0x0A, execute_minmax::<Quiet>)
                    .set(0x0B, execute_abs::<Quiet>)
                )
                .set(0xB8, execute_sgn::<Quiet>)
                .set(0xB9, execute_less::<Quiet>)
                .set(0xBA, execute_equal::<Quiet>)
                .set(0xBB, execute_leq::<Quiet>)
                .set(0xBC, execute_greater::<Quiet>)
                .set(0xBD, execute_neq::<Quiet>)
                .set(0xBE, execute_geq::<Quiet>)
                .set(0xBF, execute_cmp::<Quiet>)
                //0xC0
                .set(0xC0, execute_eqint::<Quiet>)
                .set(0xC1, execute_lessint::<Quiet>)
                .set(0xC2, execute_gtint::<Quiet>)
                .set(0xC3, execute_neqint::<Quiet>)
            )
    }

    fn add_code_page_0_comparsion(&mut self) -> &mut Handlers {
        self
            .set(0xB8, execute_sgn::<Signaling>)
            .set(0xB9, execute_less::<Signaling>)
            .set(0xBA, execute_equal::<Signaling>)
            .set(0xBB, execute_leq::<Signaling>)
            .set(0xBC, execute_greater::<Signaling>)
            .set(0xBD, execute_neq::<Signaling>)
            .set(0xBE, execute_geq::<Signaling>)
            .set(0xBF, execute_cmp::<Signaling>)
            //0xC0
            .set(0xC0, execute_eqint::<Signaling>)
            .set(0xC1, execute_lessint::<Signaling>)
            .set(0xC2, execute_gtint::<Signaling>)
            .set(0xC3, execute_neqint::<Signaling>)
            .set(0xC4, execute_isnan)
            .set(0xC5, execute_chknan);
        let mut c7_handlers = Handlers::new();
        c7_handlers
            .set(0x00, execute_sempty)
            .set(0x01, execute_sdempty)
            .set(0x02, execute_srempty)
            .set(0x03, execute_sdfirst)
            .set(0x04, execute_sdlexcmp)
            .set(0x05, execute_sdeq)
            .set(0x08, execute_sdpfx)
            .set(0x09, execute_sdpfxrev)
            .set(0x0A, execute_sdppfx)
            .set(0x0B, execute_sdppfxrev)
            .set(0x0C, execute_sdsfx)
            .set(0x0D, execute_sdsfxrev)
            .set(0x0E, execute_sdpsfx)
            .set(0x0F, execute_sdpsfxrev)
            .set(0x10, execute_sdcntlead0)
            .set(0x11, execute_sdcntlead1)
            .set(0x12, execute_sdcnttrail0)
            .set(0x13, execute_sdcnttrail1);
        #[cfg(feature = "gosh")] {
            c7_handlers
                .set(0x14, execute_diff)
                .set(0x15, execute_diff_patch_not_quiet)
                .set(0x16, execute_zip)
                .set(0x17, execute_unzip)
                .set(0x18, execute_diff_zip)
                .set(0x19, execute_diff_patch_zip_not_quiet)
                .set(0x20, execute_diff_patch_quiet)
                .set(0x21, execute_diff_patch_zip_quiet)
                .set(0x22, execute_diff_patch_binary_not_quiet)
                .set(0x23, execute_diff_patch_binary_zip_not_quiet)
                .set(0x24, execute_diff_patch_binary_quiet)
                .set(0x25, execute_diff_patch_binary_zip_quiet);
        }
        self.add_subset(0xC7, &mut c7_handlers)
    }

    fn add_code_page_0_cell(&mut self) -> &mut Handlers {
        self
            .set(0xC8, execute_newc)
            .set(0xC9, execute_endc)
            .set(0xCA, execute_sti)
            .set(0xCB, execute_stu)
            .set(0xCC, execute_stref)
            .set(0xCD, execute_endcst)
            .set(0xCE, execute_stslice)
            .add_subset(0xCF, Handlers::new()
                .set(0x00, execute_stix)
                .set(0x01, execute_stux)
                .set(0x02, execute_stixr)
                .set(0x03, execute_stuxr)
                .set(0x04, execute_stixq)
                .set(0x05, execute_stuxq)
                .set(0x06, execute_stixrq)
                .set(0x07, execute_stuxrq)
                .set(0x08, execute_sti)
                .set(0x09, execute_stu)
                .set(0x0A, execute_stir)
                .set(0x0B, execute_stur)
                .set(0x0C, execute_stiq)
                .set(0x0D, execute_stuq)
                .set(0x0E, execute_stirq)
                .set(0x0F, execute_sturq)
                .set(0x10, execute_stref)
                .set(0x11, execute_stbref)
                .set(0x12, execute_stslice)
                .set(0x13, execute_stb)
                .set(0x14, execute_strefr)
                .set(0x15, execute_endcst)
                .set(0x16, execute_stslicer)
                .set(0x17, execute_stbr)
                .set(0x18, execute_strefq)
                .set(0x19, execute_stbrefq)
                .set(0x1A, execute_stsliceq)
                .set(0x1B, execute_stbq)
                .set(0x1C, execute_strefrq)
                .set(0x1D, execute_stbrefrq)
                .set(0x1E, execute_stslicerq)
                .set(0x1F, execute_stbrq)
                .set(0x20, execute_strefconst)
                .set(0x21, execute_stref2const)
                .set(0x23, execute_endxc)
                .set(0x28, execute_stile4)
                .set(0x29, execute_stule4)
                .set(0x2A, execute_stile8)
                .set(0x2B, execute_stule8)
                .set(0x30, execute_bdepth)
                .set(0x31, execute_bbits)
                .set(0x32, execute_brefs)
                .set(0x33, execute_bbitrefs)
                .set(0x35, execute_brembits)
                .set(0x36, execute_bremrefs)
                .set(0x37, execute_brembitrefs)
                .set(0x38, execute_bchkbits_short)
                .set(0x39, execute_bchkbits_long)
                .set(0x3A, execute_bchkrefs)
                .set(0x3B, execute_bchkbitrefs)
                .set(0x3C, execute_bchkbitsq_short)
                .set(0x3D, execute_bchkbitsq_long)
                .set(0x3E, execute_bchkrefsq)
                .set(0x3F, execute_bchkbitrefsq)
                .set(0x40, execute_stzeroes)
                .set(0x41, execute_stones)
                .set(0x42, execute_stsame)
                .set(0x43, execute_stcont)
                .set_range(0x80..0xFF, execute_stsliceconst)
                .set(0xFF, execute_stsliceconst)
            )
            //0xD0
            .set(0xD0, execute_ctos)
            .set(0xD1, execute_ends)
            .set(0xD2, execute_ldi)
            .set(0xD3, execute_ldu)
            .set(0xD4, execute_ldref)
            .set(0xD5, execute_ldrefrtos)
            .set(0xD6, execute_ldslice)
            .add_subset(0xD7, Handlers::new()
                .set(0x00, execute_ldix)
                .set(0x01, execute_ldux)
                .set(0x02, execute_pldix)
                .set(0x03, execute_pldux)
                .set(0x04, execute_ldixq)
                .set(0x05, execute_lduxq)
                .set(0x06, execute_pldixq)
                .set(0x07, execute_plduxq)
                .set(0x08, execute_ldi)
                .set(0x09, execute_ldu)
                .set(0x0A, execute_pldi)
                .set(0x0B, execute_pldu)
                .set(0x0C, execute_ldiq)
                .set(0x0D, execute_lduq)
                .set(0x0E, execute_pldiq)
                .set(0x0F, execute_plduq)
                .set_range(0x10..0x18, execute_plduz)
                .set(0x18, execute_ldslicex)
                .set(0x19, execute_pldslicex)
                .set(0x1A, execute_ldslicexq)
                .set(0x1B, execute_pldslicexq)
                .set(0x1C, execute_ldslice)
                .set(0x1D, execute_pldslice)
                .set(0x1E, execute_ldsliceq)
                .set(0x1F, execute_pldsliceq)
                .set(0x20, execute_pldslicex)
                .set(0x21, execute_sdskipfirst)
                .set(0x22, execute_sdcutlast)
                .set(0x23, execute_sdskiplast)
                .set(0x24, execute_sdsubstr)
                .set(0x26, execute_sdbeginsx)
                .set(0x27, execute_sdbeginsxq)
                .set_range(0x28..0x2C, execute_sdbegins)
                .set_range(0x2C..0x30, execute_sdbeginsq)
                .set(0x30, execute_scutfirst)
                .set(0x31, execute_sskipfirst)
                .set(0x32, execute_scutlast)
                .set(0x33, execute_sskiplast)
                .set(0x34, execute_subslice)
                .set(0x36, execute_split)
                .set(0x37, execute_splitq)
                .set(0x39, execute_xctos)
                .set(0x3A, execute_xload)
                .set(0x3B, execute_xloadq)
                .set(0x41, execute_schkbits)
                .set(0x42, execute_schkrefs)
                .set(0x43, execute_schkbitrefs)
                .set(0x45, execute_schkbitsq)
                .set(0x46, execute_schkrefsq)
                .set(0x47, execute_schkbitrefsq)
                .set(0x48, execute_pldrefvar)
                .set(0x49, execute_sbits)
                .set(0x4A, execute_srefs)
                .set(0x4B, execute_sbitrefs)
                .set(0x4C, execute_pldref)
                .set_range(0x4D..0x50, execute_pldrefidx)
                .set(0x50, execute_ldile4)
                .set(0x51, execute_ldule4)
                .set(0x52, execute_ldile8)
                .set(0x53, execute_ldule8)
                .set(0x54, execute_pldile4)
                .set(0x55, execute_pldule4)
                .set(0x56, execute_pldile8)
                .set(0x57, execute_pldule8)
                .set(0x58, execute_ldile4q)
                .set(0x59, execute_ldule4q)
                .set(0x5A, execute_ldile8q)
                .set(0x5B, execute_ldule8q)
                .set(0x5C, execute_pldile4q)
                .set(0x5D, execute_pldule4q)
                .set(0x5E, execute_pldile8q)
                .set(0x5F, execute_pldule8q)
                .set(0x60, execute_ldzeroes)
                .set(0x61, execute_ldones)
                .set(0x62, execute_ldsame)
                .set(0x64, execute_sdepth)
                .set(0x65, execute_cdepth)
                .set(0x66, execute_ldcont)
            )
    }

    fn add_code_page_0_control_flow(&mut self) -> &mut Handlers {
        self
            .set(0xD8, execute_callx)
            .set(0xD9, execute_jmpx)
            .set(0xDA, execute_callxargs)
            .add_subset(0xDB, Handlers::new()
                .set_range(0x00..0x10, execute_callxargs)
                .set_range(0x10..0x20, execute_jmpxargs)
                .set_range(0x20..0x30, execute_retargs)
                .set(0x30, execute_ret)
                .set(0x31, execute_retalt)
                .set(0x32, execute_retbool)
                .set(0x34, execute_callcc)
                .set(0x35, execute_jmpxdata)
                .set(0x36, execute_callccargs)
                .set(0x38, execute_callxva)
                .set(0x39, execute_retva)
                .set(0x3A, execute_jmpxva)
                .set(0x3B, execute_callccva)
                .set(0x3C, execute_callref)
                .set(0x3D, execute_jmpref)
                .set(0x3E, execute_jmprefdata)
                .set(0x3F, execute_retdata)
            )
            .set(0xDE, execute_if)
            .set(0xDC, execute_ifret)
            .set(0xDD, execute_ifnotret)
            .set(0xDF, execute_ifnot)
            .set(0xE0, execute_ifjmp)
            .set(0xE1, execute_ifnotjmp)
            .set(0xE2, execute_ifelse)
            .add_subset(0xE3, Handlers::new()
                .set(0x00, execute_ifref)
                .set(0x01, execute_ifnotref)
                .set(0x02, execute_ifjmpref)
                .set(0x03, execute_ifnotjmpref)
                .set(0x04, execute_condsel)
                .set(0x05, execute_condselchk)
                .set(0x08, execute_ifretalt)
                .set(0x09, execute_ifnotretalt)
                .set(0x0D, execute_ifrefelse)
                .set(0x0E, execute_ifelseref)
                .set(0x0F, execute_ifrefelseref)
                .set(0x14, execute_repeat_break)
                .set(0x15, execute_repeatend_break)
                .set(0x16, execute_until_break)
                .set(0x17, execute_untilend_break)
                .set(0x18, execute_while_break)
                .set(0x19, execute_whileend_break)
                .set(0x1A, execute_again_break)
                .set(0x1B, execute_againend_break)
                .set_range(0x80..0xA0, execute_ifbitjmp)
                .set_range(0xA0..0xC0, execute_ifnbitjmp)
                .set_range(0xC0..0xE0, execute_ifbitjmpref)
                .set_range(0xE0..0xFF, execute_ifnbitjmpref)
                .set(0xFF, execute_ifnbitjmpref)
             )
            .set(0xE4, execute_repeat)
            .set(0xE5, execute_repeatend)
            .set(0xE6, execute_until)
            .set(0xE7, execute_untilend)
            .set(0xE8, execute_while)
            .set(0xE9, execute_whileend)
            .set(0xEA, execute_again)
            .set(0xEB, execute_againend)
            .set(0xEC, execute_setcontargs)
            .add_subset(0xED, Handlers::new()
                .set_range(0x00..0x10, execute_returnargs)
                .set(0x10, execute_returnva)
                .set(0x11, execute_setcontva)
                .set(0x12, execute_setnumvarargs)
                .set(0x1E, execute_bless)
                .set(0x1F, execute_blessva)
                .set_range(0x40..0x50, execute_pushctr)
                .set_range(0x50..0x60, execute_popctr)
                .set_range(0x60..0x70, execute_setcontctr)
                .set_range(0x70..0x80, execute_setretctr)
                .set_range(0x80..0x90, execute_setaltctr)
                .set_range(0x90..0xA0, execute_popsave)
                .set_range(0xA0..0xB0, execute_save)
                .set_range(0xB0..0xC0, execute_savealt)
                .set_range(0xC0..0xD0, execute_saveboth)
                // 0xEDE0
                .set(0xE0, execute_pushctrx)
                .set(0xE1, execute_popctrx)
                .set(0xE2, execute_setcontctrx)
                // 0xEDF0
                .set(0xF0, execute_compos)
                .set(0xF1, execute_composalt)
                .set(0xF2, execute_composboth)
                .set(0xF3, execute_atexit)
                .set(0xF4, execute_atexitalt)
                .set(0xF5, execute_setexitalt)
                .set(0xF6, execute_thenret)
                .set(0xF7, execute_thenretalt)
                .set(0xF8, execute_invert)
                .set(0xF9, execute_booleval)
                .set(0xFA, execute_samealt)
                .set(0xFB, execute_samealt_save)
            )
            .set(0xEE, execute_blessargs)
            .set(0xF0, execute_call_short)
            .add_subset(0xF1, Handlers::new()
                .set_range(0x00..0x40, execute_call_long)
                .set_range(0x40..0x80, execute_jmp)
                .set_range(0x80..0xC0, execute_prepare)
            )
    }

    fn add_code_page_0_exceptions(&mut self) -> &mut Handlers {
        self
            .add_subset(0xF2, Handlers::new()
                .set_range(0x00..0x40, execute_throw_short)
                .set_range(0x40..0x80, execute_throwif_short)
                .set_range(0x80..0xC0, execute_throwifnot_short)
                .set_range(0xC0..0xC8, execute_throw_long)
                .set_range(0xC8..0xD0, execute_throwarg)
                .set_range(0xD0..0xD8, execute_throwif_long)
                .set_range(0xD8..0xE0, execute_throwargif)
                .set_range(0xE0..0xE8, execute_throwifnot_long)
                .set_range(0xE8..0xF0, execute_throwargifnot)
                .set(0xF0, execute_throwany)
                .set(0xF1, execute_throwargany)
                .set(0xF2, execute_throwanyif)
                .set(0xF3, execute_throwarganyif)
                .set(0xF4, execute_throwanyifnot)
                .set(0xF5, execute_throwarganyifnot)
                .set(0xFE, execute_trykeep)
                .set(0xFF, execute_try)
            )
            .set(0xF3, execute_tryargs)
    }

    fn add_code_page_0_blockchain(&mut self) -> &mut Handlers {
        self
            .add_subset(0xFA, Handlers::new()
                .set(0x00, execute_ldgrams)
                .set(0x01, execute_ldvarint16)
                .set(0x02, execute_stgrams)
                .set(0x03, execute_stvarint16)
                .set(0x04, execute_ldvaruint32)
                .set(0x05, execute_ldvarint32)
                .set(0x06, execute_stvaruint32)
                .set(0x07, execute_stvarint32)
                .set(0x40, execute_ldmsgaddr::<Signaling>)
                .set(0x41, execute_ldmsgaddr::<Quiet>)
                .set(0x42, execute_parsemsgaddr::<Signaling>)
                .set(0x43, execute_parsemsgaddr::<Quiet>)
                .set(0x44, execute_rewrite_std_addr::<Signaling>)
                .set(0x45, execute_rewrite_std_addr::<Quiet>)
                .set(0x46, execute_rewrite_var_addr::<Signaling>)
                .set(0x47, execute_rewrite_var_addr::<Quiet>)
            )
            .add_subset(0xFB, Handlers::new()
                .set(0x00, execute_sendrawmsg)
                .set(0x02, execute_rawreserve)
                .set(0x03, execute_rawreservex)
                .set(0x04, execute_setcode)
                .set(0x06, execute_setlibcode)
                .set(0x07, execute_changelib)
                .set(0x0A, execute_copyleft)
            )
    }

    fn add_code_page_0_dictionaries(&mut self) -> &mut Handlers {
        self
            .add_subset(0xF4, Handlers::new()
                .set(0x00, execute_stdict)
                .set(0x01, execute_skipdict)
                .set(0x02, execute_lddicts)
                .set(0x03, execute_plddicts)
                .set(0x04, execute_lddict)
                .set(0x05, execute_plddict)
                .set(0x06, execute_lddictq)
                .set(0x07, execute_plddictq)
                .set(0x0A, execute_dictget)
                .set(0x0B, execute_dictgetref)
                .set(0x0C, execute_dictiget)
                .set(0x0D, execute_dictigetref)
                .set(0x0E, execute_dictuget)
                .set(0x0F, execute_dictugetref)
                .set(0x12, execute_dictset)
                .set(0x13, execute_dictsetref)
                .set(0x14, execute_dictiset)
                .set(0x15, execute_dictisetref)
                .set(0x16, execute_dictuset)
                .set(0x17, execute_dictusetref)
                .set(0x1A, execute_dictsetget)
                .set(0x1B, execute_dictsetgetref)
                .set(0x1C, execute_dictisetget)
                .set(0x1D, execute_dictisetgetref)
                .set(0x1E, execute_dictusetget)
                .set(0x1F, execute_dictusetgetref)
                .set(0x22, execute_dictreplace)
                .set(0x23, execute_dictreplaceref)
                .set(0x24, execute_dictireplace)
                .set(0x25, execute_dictireplaceref)
                .set(0x26, execute_dictureplace)
                .set(0x27, execute_dictureplaceref)
                .set(0x2A, execute_dictreplaceget)
                .set(0x2B, execute_dictreplacegetref)
                .set(0x2C, execute_dictireplaceget)
                .set(0x2D, execute_dictireplacegetref)
                .set(0x2E, execute_dictureplaceget)
                .set(0x2F, execute_dictureplacegetref)
                .set(0x32, execute_dictadd)
                .set(0x33, execute_dictaddref)
                .set(0x34, execute_dictiadd)
                .set(0x35, execute_dictiaddref)
                .set(0x36, execute_dictuadd)
                .set(0x37, execute_dictuaddref)
                .set(0x3A, execute_dictaddget)
                .set(0x3B, execute_dictaddgetref)
                .set(0x3C, execute_dictiaddget)
                .set(0x3D, execute_dictiaddgetref)
                .set(0x3E, execute_dictuaddget)
                .set(0x3F, execute_dictuaddgetref)
                .set(0x41, execute_dictsetb)
                .set(0x42, execute_dictisetb)
                .set(0x43, execute_dictusetb)
                .set(0x45, execute_dictsetgetb)
                .set(0x46, execute_dictisetgetb)
                .set(0x47, execute_dictusetgetb)
                .set(0x49, execute_dictreplaceb)
                .set(0x4A, execute_dictireplaceb)
                .set(0x4B, execute_dictureplaceb)
                .set(0x4D, execute_dictreplacegetb)
                .set(0x4E, execute_dictireplacegetb)
                .set(0x4F, execute_dictureplacegetb)
                .set(0x51, execute_dictaddb)
                .set(0x52, execute_dictiaddb)
                .set(0x53, execute_dictuaddb)
                .set(0x55, execute_dictaddgetb)
                .set(0x56, execute_dictiaddgetb)
                .set(0x57, execute_dictuaddgetb)
                .set(0x59, execute_dictdel)
                .set(0x5A, execute_dictidel)
                .set(0x5B, execute_dictudel)
                .set(0x62, execute_dictdelget)
                .set(0x63, execute_dictdelgetref)
                .set(0x64, execute_dictidelget)
                .set(0x65, execute_dictidelgetref)
                .set(0x66, execute_dictudelget)
                .set(0x67, execute_dictudelgetref)
                .set(0x69, execute_dictgetoptref)
                .set(0x6A, execute_dictigetoptref)
                .set(0x6B, execute_dictugetoptref)
                .set(0x6D, execute_dictsetgetoptref)
                .set(0x6E, execute_dictisetgetoptref)
                .set(0x6F, execute_dictusetgetoptref)
                .set(0x70, execute_pfxdictset)
                .set(0x71, execute_pfxdictreplace)
                .set(0x72, execute_pfxdictadd)
                .set(0x73, execute_pfxdictdel)
                .set(0x74, execute_dictgetnext)
                .set(0x75, execute_dictgetnexteq)
                .set(0x76, execute_dictgetprev)
                .set(0x77, execute_dictgetpreveq)
                .set(0x78, execute_dictigetnext)
                .set(0x79, execute_dictigetnexteq)
                .set(0x7A, execute_dictigetprev)
                .set(0x7B, execute_dictigetpreveq)
                .set(0x7C, execute_dictugetnext)
                .set(0x7D, execute_dictugetnexteq)
                .set(0x7E, execute_dictugetprev)
                .set(0x7F, execute_dictugetpreveq)
                .set(0x82, execute_dictmin)
                .set(0x83, execute_dictminref)
                .set(0x84, execute_dictimin)
                .set(0x85, execute_dictiminref)
                .set(0x86, execute_dictumin)
                .set(0x87, execute_dictuminref)
                .set(0x8A, execute_dictmax)
                .set(0x8B, execute_dictmaxref)
                .set(0x8C, execute_dictimax)
                .set(0x8D, execute_dictimaxref)
                .set(0x8E, execute_dictumax)
                .set(0x8F, execute_dictumaxref)
                .set(0x92, execute_dictremmin)
                .set(0x93, execute_dictremminref)
                .set(0x94, execute_dictiremmin)
                .set(0x95, execute_dictiremminref)
                .set(0x96, execute_dicturemmin)
                .set(0x97, execute_dicturemminref)
                .set(0x9A, execute_dictremmax)
                .set(0x9B, execute_dictremmaxref)
                .set(0x9C, execute_dictiremmax)
                .set(0x9D, execute_dictiremmaxref)
                .set(0x9E, execute_dicturemmax)
                .set(0x9F, execute_dicturemmaxref)
                .set(0xA0, execute_dictigetjmp)
                .set(0xA1, execute_dictugetjmp)
                .set(0xA2, execute_dictigetexec)
                .set(0xA3, execute_dictugetexec)
                .set_range(0xA4..0xA8, execute_dictpushconst)
                .set(0xA8, execute_pfxdictgetq)
                .set(0xA9, execute_pfxdictget)
                .set(0xAA, execute_pfxdictgetjmp)
                .set(0xAB, execute_pfxdictgetexec)
                .set_range(0xAC..0xAF, execute_pfxdictswitch)
                .set(0xAF, execute_pfxdictswitch)
                .set(0xB1, execute_subdictget)
                .set(0xB2, execute_subdictiget)
                .set(0xB3, execute_subdictuget)
                .set(0xB5, execute_subdictrpget)
                .set(0xB6, execute_subdictirpget)
                .set(0xB7, execute_subdicturpget)
                .set(0xBC, execute_dictigetjmpz)
                .set(0xBD, execute_dictugetjmpz)
                .set(0xBE, execute_dictigetexecz)
                .set(0xBF, execute_dictugetexecz)
            )
    }

    /// Gas and configuration primitives handlers
    fn add_code_page_0_gas_rand_config(&mut self) -> &mut Handlers {
        self
            .add_subset(0xF8, Handlers::new()
                .set(0x00, execute_accept)
                .set(0x01, execute_setgaslimit)
                .set(0x02, execute_buygas)
                .set(0x04, execute_gramtogas)
                .set(0x05, execute_gastogram)
                .set(0x06, execute_gas_remaining)
                .set(0x0F, execute_commit)
                .set(0x10, execute_randu256)
                .set(0x11, execute_rand)
                .set(0x14, execute_setrand)
                .set(0x15, execute_addrand)
                .set(0x20, execute_getparam)
                .set(0x21, execute_getparam)
                .set(0x22, execute_getparam)
                .set(0x23, execute_now)
                .set(0x24, execute_blocklt)
                .set(0x25, execute_ltime)
                .set(0x26, execute_randseed)
                .set(0x27, execute_balance)
                .set(0x28, execute_my_addr)
                .set(0x29, execute_config_root)
                .set(0x2A, execute_my_code)
                .set(0x2B, execute_init_code_hash)
                .set(0x2C, execute_storage_fees_collected)
                .set(0x2D, execute_seq_no)
                .set(0x30, execute_config_dict)
                .set(0x32, execute_config_ref_param)
                .set(0x33, execute_config_opt_param)
                .set(0x40, execute_getglobvar)
                .set_range(0x41..0x5F, execute_getglob)
                .set(0x5F, execute_getglob)
                .set(0x60, execute_setglobvar)
                .set_range(0x61..0x7F, execute_setglob)
                .set(0x7F, execute_setglob)
            )
    }

    /// Hashing and cryptography primitives handlers
    fn add_code_page_0_crypto(&mut self) -> &mut Handlers {
        self
        .add_subset(0xF9, Handlers::new()
            .set(0x00, execute_hashcu)
            .set(0x01, execute_hashsu)
            .set(0x02, execute_sha256u)
            .set(0x10, execute_chksignu)
            .set(0x11, execute_chksigns)
            .set(0x12, execute_vergrth16)
            .set(0x40, execute_cdatasizeq)
            .set(0x41, execute_cdatasize)
            .set(0x42, execute_sdatasizeq)
            .set(0x43, execute_sdatasize)
            .set(0x44, execute_find_by_init_code_hash)
            .set(0x45, execute_find_by_code_hash)
            .set(0x46, execute_find_by_data_hash)
            .set(0x50, execute_try_elect)
        )
    }
    /// Dumping functions
    fn add_code_page_0_debug(&mut self) -> &mut Handlers {
        self.add_subset(0xFE, Handlers::new()
            .set(0x00, execute_dump_stack)
            .set_range(0x01..0x0F, execute_dump_stack_top)
            .set(0x10, execute_dump_hex)
            .set(0x11, execute_print_hex)
            .set(0x12, execute_dump_bin)
            .set(0x13, execute_print_bin)
            .set(0x14, execute_dump_str)
            .set(0x15, execute_print_str)
            .set(0x1E, execute_debug_off)
            .set(0x1F, execute_debug_on)
            .set_range(0x20..0x2F, execute_dump_var)
            .set_range(0x30..0x3F, execute_print_var)
            .set_range(0xF0..0xFF, execute_dump_string)
            .set(0xFF, execute_dump_string)
        )
    }

    pub(super) fn get_handler(&self, engine: &mut Engine) -> Result<ExecuteHandler> {
        let cmd = engine.next_cmd()?;
        // log::debug!(target: "tvm", "get_handler cmd: {:X}\n", cmd);
        match self.directs[cmd as usize] {
            Some(Handler::Direct(handler)) => Ok(handler),
            Some(Handler::Subset(i)) => self.subsets[i].get_handler(engine),
            None => Ok(execute_unknown)
        }
    }

    fn add_subset(&mut self, code: u8, subset: &mut Handlers) -> &mut Handlers {
        match self.directs[code as usize] {
            Some(Handler::Direct(x)) => {
                if x as usize == execute_unknown as usize {
                    self.directs[code as usize] = Some(Handler::Subset(self.subsets.len()));
                    self.subsets.push(std::mem::replace(subset, Handlers::new()))
                } else {
                    panic!("Slot for subset {:02x} is already occupied", code)
                }
            }
            None => {
                self.directs[code as usize] = Some(Handler::Subset(self.subsets.len()));
                self.subsets.push(std::mem::replace(subset, Handlers::new()))
            }
            _ => panic!("Subset {:02x} is already registered", code),
        }
        self
    }

    fn register_handler(&mut self, code: u8, handler: ExecuteHandler) {
        match self.directs[code as usize] {
            None => self.directs[code as usize] = Some(Handler::Direct(handler)),
            Some(Handler::Direct(x)) => {
                if x as usize == execute_unknown as usize {
                    self.directs[code as usize] = Some(Handler::Direct(handler))
                } else {
                    panic!("Code {:02x} is already registered", code)
                }
            }
            _ => panic!("Slot for code {:02x} is already occupied", code)
        }
    }

    fn set(&mut self, code: u8, handler: ExecuteHandler) -> &mut Handlers {
        self.register_handler(code, handler);
        self
    }

    fn set_range(&mut self, codes: Range<u8>, handler: ExecuteHandler) -> &mut Handlers {
        for code in codes {
            self.register_handler(code, handler);
        }
        self
    }
}

fn print_handlers(handlers: &Handlers, f: &mut fmt::Formatter, indent: String) -> fmt::Result {
    for h in 0..handlers.directs.len() {
        match handlers.directs[h] {
            Some(Handler::Direct(func)) => {
                writeln!(f, "{}{:02x}: 0x{:x}", indent, h, func as *const u8 as usize)?
            }
            Some(Handler::Subset(i)) => {
                writeln!(f, "{}{:02x}: subset", indent, h)?;
                print_handlers(&handlers.subsets[i], f, format!("  {}", indent))?;
            }
            None => {}
        }
    }
    fmt::Result::Ok(())
}

impl fmt::Debug for Handlers {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        print_handlers(self, f, String::new())
    }
}
