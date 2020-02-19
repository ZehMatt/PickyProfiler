#pragma once

#include <Zydis/Zydis.h>
#include <vector>

namespace Picky {

using DecodedInstructions = std::vector<ZydisDecodedInstruction>;

template<typename FTerm>
static DecodedInstructions DecodeUntil(uintptr_t source, const FTerm& term)
{
    DecodedInstructions decoded;

    ZydisDecoder decoder;
#ifdef _M_X64
    ZydisDecoderInit(
        &decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_ADDRESS_WIDTH_64);
#else
    ZydisDecoderInit(
        &decoder, ZYDIS_MACHINE_MODE_LONG_COMPAT_32, ZYDIS_ADDRESS_WIDTH_32);
#endif

    bool hasPushRax = false;
    bool hasMov = false;
    bool hasXchg = false;

    for (uintptr_t va = source;;)
    {
        ZydisDecodedInstruction* ins = &decoded.emplace_back();

        auto status = ZydisDecoderDecodeBuffer(
            &decoder, reinterpret_cast<const void*>(va), 16, va, ins);
        if (status != ZYDIS_STATUS_SUCCESS)
        {
            Logging::Msg("Unable to decode instruction at %p", va);

            // Destroy last.
            decoded.pop_back();

            break;
        }

        if (ins->mnemonic == ZYDIS_MNEMONIC_RET
            && ins->operands[0].type == ZYDIS_OPERAND_TYPE_IMMEDIATE
            && ins->operands[0].imm.value.u == 0)
        {
            ins->operandCount = 0;
            ins->operands[0].type = ZYDIS_OPERAND_TYPE_UNUSED;
        }

        if (term(*ins))
        {
            break;
        }

        va += ins->length;
    }

    return decoded;
}

} // namespace Picky
