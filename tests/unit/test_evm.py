import pytest

from tests.conftest import SELFDESTRUCT_CONTRACT, load_bytecode
from txray.errors import BytecodeError
from txray.evm.cfg import ControlFlowGraph, build_blocks
from txray.evm.disassembler import assemble, disassemble, jumpdests
from txray.evm.metadata import parse_metadata
from txray.evm.profile import PROXY_SLOTS, extract_dispatch, profile_bytecode
from txray.hexutil import selector


class TestDisassembler:
    def test_push_immediates_are_skipped(self) -> None:
        # PUSH2 0x5b5b contains JUMPDEST bytes that must not count as jump targets.
        code = bytes.fromhex("615b5b5b00")
        ins = disassemble(code)
        assert [i.name for i in ins] == ["PUSH2", "JUMPDEST", "STOP"]
        assert jumpdests(code) == {3}

    def test_truncated_push_is_zero_padded(self) -> None:
        ins = disassemble(bytes.fromhex("62ff"))
        assert ins[0].arg == b"\xff\x00\x00"

    def test_unknown_opcode(self) -> None:
        assert disassemble(b"\x0c")[0].name == "UNKNOWN_0x0c"

    def test_assembler_labels(self) -> None:
        code = assemble("PUSH @end JUMP end: JUMPDEST STOP")
        assert code.hex() == "61000456" + "5b00"

    def test_assembler_errors(self) -> None:
        with pytest.raises(BytecodeError):
            assemble("FOO")
        with pytest.raises(BytecodeError):
            assemble("PUSH1 0x1234")
        with pytest.raises(BytecodeError):
            assemble("PUSH @missing")


class TestCfg:
    def test_blocks_split_at_jumpdest_and_jumps(self) -> None:
        blocks = build_blocks(disassemble(SELFDESTRUCT_CONTRACT))
        assert 0 in blocks
        assert all(b.instructions for b in blocks.values())

    def test_internal_call_return_is_resolved_per_caller(self) -> None:
        # Two call sites share one internal function; each pushes its own return label.
        code = assemble(
            """
            PUSH @ret1 PUSH @fn JUMP
            ret1: JUMPDEST PUSH @ret2 PUSH @fn JUMP
            ret2: JUMPDEST STOP
            fn: JUMPDEST JUMP
            """
        )
        cfg = ControlFlowGraph(disassemble(code))
        result = cfg.explore(0)
        assert result.complete
        ret1, ret2, fn = sorted(jumpdests(code))
        assert result.edges[fn] == {ret1, ret2}

    def test_dynamic_jump_is_reported(self) -> None:
        code = assemble("PUSH1 0x00 CALLDATALOAD JUMP")
        result = ControlFlowGraph(disassemble(code)).explore(0)
        assert result.unresolved == {0}
        assert not result.complete

    def test_unreachable_code_is_not_reachable(self) -> None:
        code = assemble("STOP dead: JUMPDEST CALLER SELFDESTRUCT")
        cfg = ControlFlowGraph(disassemble(code))
        assert "SELFDESTRUCT" not in cfg.opcodes_in(cfg.explore(0).reachable)

    def test_loops_terminate(self) -> None:
        code = assemble(
            """
            PUSH1 0x00
            loop: JUMPDEST PUSH1 0x01 ADD DUP1 PUSH2 0xffff GT PUSH @loop JUMPI STOP
            """
        )
        result = ControlFlowGraph(disassemble(code)).explore(0)
        assert result.complete

    def test_delegatecall_constant_target_is_tracked(self) -> None:
        lib = 0x800C32EAA2A6C93CF4CB51794450ED77FBFBB172
        code = assemble(
            f"""
            PUSH1 0 PUSH1 0 PUSH1 0 PUSH1 0 PUSH20 {hex(lib)} PUSH @go JUMP
            go: JUMPDEST GAS DELEGATECALL STOP
            """
        )
        result = ControlFlowGraph(disassemble(code)).explore(0)
        assert set().union(*result.delegatecalls.values()) == {lib}


class TestMetadata:
    def test_solc_ipfs_trailer(self) -> None:
        meta = parse_metadata(load_bytecode("usdc_impl"))
        assert meta is not None
        assert meta.compiler == "solc 0.6.12"
        assert meta.source_hash is not None
        assert meta.source_hash.startswith("ipfs:1220")

    def test_solc_version_only_trailer(self) -> None:
        # Permit2 was compiled with bytecodeHash = none: only the compiler version remains.
        meta = parse_metadata(load_bytecode("permit2"))
        assert meta is not None
        assert meta.compiler == "solc 0.8.17"
        assert meta.source_hash is None

    def test_legacy_bzzr0_trailer(self) -> None:
        meta = parse_metadata(load_bytecode("weth9"))
        assert meta is not None
        assert meta.compiler is None
        assert meta.source_hash is not None
        assert meta.source_hash.startswith("bzzr0:")

    @pytest.mark.parametrize("code", [b"", b"\x00\x01", bytes.fromhex("6000ffff"), b"\xa1\x00\x01"])
    def test_garbage_is_ignored(self, code: bytes) -> None:
        assert parse_metadata(code) is None


class TestProfile:
    def test_proxy_slot_constants(self) -> None:
        assert PROXY_SLOTS["eip1967.implementation"] == int(
            "360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc", 16
        )
        assert PROXY_SLOTS["zeppelinos.implementation"] == int(
            "7050c9e0f4ca769c69bd3a8ef740bc37934f8e2c036e5a723fd8ee048ed3f8c3", 16
        )

    def test_selfdestruct_reachability_per_function(self) -> None:
        profile_bytecode.cache_clear()
        profile = profile_bytecode(SELFDESTRUCT_CONTRACT)
        kill = profile.function(selector("kill()"))
        withdraw = profile.function(selector("withdraw()"))
        assert kill is not None and "SELFDESTRUCT" in kill.reaches
        assert withdraw is not None and "SELFDESTRUCT" not in withdraw.reaches
        bc001 = next(f for f in profile.findings if f.rule_id == "BC001")
        assert bc001.evidence["functions"] == ["kill()"]

    def test_weth9(self) -> None:
        profile = profile_bytecode(load_bytecode("weth9"))
        names = {n for f in profile.functions for n in f.names}
        assert {"deposit()", "withdraw(uint256)", "approve(address,uint256)"} <= names
        assert len(profile.functions) == 11
        assert profile.cfg_complete
        assert profile.findings == []

    def test_usdc_proxy(self) -> None:
        profile = profile_bytecode(load_bytecode("usdc_proxy"))
        assert profile.proxy_slots == ["zeppelinos.implementation"]
        assert profile.is_proxy
        assert profile.implements(selector("transfer(address,uint256)")) is None
        assert "BC005" in {f.rule_id for f in profile.findings}

    def test_usdc_implementation_capabilities(self) -> None:
        profile = profile_bytecode(load_bytecode("usdc_impl"))
        bc006 = next(f for f in profile.findings if f.rule_id == "BC006")
        assert {"blacklist", "mint", "pause"} <= set(bc006.evidence["capabilities"])
        # The only DELEGATECALL target is a linked library constant, so no BC002.
        assert not profile.dynamic_delegatecall
        assert profile.delegatecall_constant_targets
        assert "BC002" not in {f.rule_id for f in profile.findings}

    def test_permit2_and_multicall3_cfg_complete(self) -> None:
        for name in ("permit2", "multicall3"):
            profile = profile_bytecode(load_bytecode(name))
            assert profile.cfg_complete, name
            assert "SELFDESTRUCT" not in profile.reachable_opcodes

    def test_minimal_proxy(self) -> None:
        impl = bytes.fromhex("bebebebebebebebebebebebebebebebebebebebe")
        code = (
            bytes.fromhex("363d3d373d3d3d363d73")
            + impl
            + bytes.fromhex("5af43d82803e903d91602b57fd5bf3")
        )
        profile = profile_bytecode(code)
        assert profile.minimal_proxy_target is not None
        assert profile.minimal_proxy_target.lower() == "0x" + impl.hex()
        assert [f.rule_id for f in profile.findings] == ["BC004"]

    def test_empty_code(self) -> None:
        assert [f.rule_id for f in profile_bytecode(b"").findings] == ["BC010"]

    def test_metamorphic_pattern(self) -> None:
        code = assemble("PUSH1 0 PUSH1 0 PUSH1 0 PUSH1 0 CREATE2 POP CALLER SELFDESTRUCT")
        rules = {f.rule_id for f in profile_bytecode(code).findings}
        assert {"BC001", "BC007"} <= rules

    def test_tx_origin(self) -> None:
        code = assemble("ORIGIN CALLER EQ PUSH @ok JUMPI PUSH1 0 DUP1 REVERT ok: JUMPDEST STOP")
        assert "BC003" in {f.rule_id for f in profile_bytecode(code).findings}

    def test_dispatch_patterns(self) -> None:
        legacy = assemble("DUP1 PUSH4 0x11223344 EQ PUSH @a JUMPI a: JUMPDEST STOP")
        via_ir = assemble("PUSH4 0x11223344 DUP2 EQ PUSH @a JUMPI a: JUMPDEST STOP")
        for code in (legacy, via_ir):
            assert set(extract_dispatch(disassemble(code))) == {bytes.fromhex("11223344")}
