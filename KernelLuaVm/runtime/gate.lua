R"(
    -- gate.lua - admission-gate policy compiler.
    --
    -- Turns readable condition tables into the flat 5-word instruction stream
    -- the driver's fixed interpreter evaluates on every event, before any lock
    -- (see callback.cpp "Admission gate ISA"). The driver knows nothing about
    -- syscalls, PIDs or offsets - all meaning is assembled here, in script.
    --
    --   SetGate(eid, gate.compile{
    --       -- row: every condition must hold (AND); rows are ORed
    --       { {arg=0, range={0x1000, 0x1FFF}}, {arg=2, allbits=0x40} },
    --       { {stack=0xF8, mask=0xFFF, eq=0x236} },
    --   })
    --
    -- Condition fields:
    --   arg = 0..15   compare captured argument N
    --   stack = off   compare the 8 bytes at [rsp+off] (trap-frame walk,
    --                 bounded to the live kernel stack, off <= 0xFFF)
    --   thread = off  compare the 8 bytes at [kthread+off] (the KTHREAD
    --                 captured at trap time, off <= 0x500)
    --   mask = m      optional, value & m before the compare
    --   one of: eq= v, ne= v, lt= v, gt= v, le= v, ge= v,
    --           range= {lo, hi}, anybits= v, allbits= v
    --
    -- Clear with SetGate(eid) or SetGate(eid, nil).
    --
    gate = {}

    local OPS = {
        eq = 2, ne = 3, lt = 4, gt = 5, le = 6, ge = 7,
        range = 8, anybits = 9, allbits = 10,
    }
    local OP_NAMES = { "eq", "ne", "lt", "gt", "le", "ge", "range", "anybits", "allbits" }
    local STOP, OR = 0, 1
    local MAX_INSTRS = 32

    local function is_int(x)
        return math.type(x) == "integer"
    end

    local function compile_cond(out, c)
        local unit, index
        if c.arg ~= nil then
            unit, index = 0, c.arg
        elseif c.stack ~= nil then
            unit, index = 1, c.stack
        elseif c.thread ~= nil then
            unit, index = 2, c.thread
        else
            error("gate: condition needs arg= or stack= or thread=", 0)
        end
        if not is_int(index) or index < 0 or (unit == 0 and index > 15) or (unit == 1 and index > 0xFFF) or (unit == 2 and index > 0x500) then
            error("gate: bad selector index", 0)
        end

        local opname
        for _, name in ipairs(OP_NAMES) do
            if c[name] ~= nil then opname = name break end
        end
        if not opname then
                error("gate: condition needs one op from eq ne lt gt le ge range anybits allbits", 0)
        end

        local mask = c.mask or ~0
        if not is_int(mask) then error("gate: mask must be an integer", 0) end

        local a, b = 0, 0
        if opname == "range" then
            if type(c.range) ~= "table" or not is_int(c.range[1]) or not is_int(c.range[2]) then
                error("gate: range = {lo, hi} needs two integers", 0)
            end
            a, b = c.range[1], c.range[2]
        else
            a = c[opname]
            if not is_int(a) then error("gate: " .. opname .. " needs an integer value", 0) end
        end

        out[#out + 1] = OPS[opname]
        out[#out + 1] = unit << 32 | index
        out[#out + 1] = mask
        out[#out + 1] = a
        out[#out + 1] = b
    end

    function gate.compile(rows)
        if type(rows) ~= "table" or #rows == 0 then
            error("gate.compile: need a non-empty array of rows", 0)
        end

        local out = {}
        for r, row in ipairs(rows) do
            if type(row) ~= "table" or #row == 0 then
                error("gate.compile: row " .. r .. " must be a non-empty array of conditions", 0)
            end
            for _, c in ipairs(row) do
                compile_cond(out, c)
            end
            -- row separator: OP_OR + 4 padding words (fixed 5-word stride)
            out[#out + 1] = OR
            for _ = 1, 4 do out[#out + 1] = 0 end
        end

        -- trailing OR becomes the program terminator
        out[#out - 4] = STOP

        if #out > MAX_INSTRS * 5 then
            error("gate.compile: program exceeds " .. MAX_INSTRS .. " instructions", 0)
        end
        return out
    end
)"
